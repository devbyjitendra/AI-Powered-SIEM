from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from datetime import datetime, timedelta
from sqlalchemy import func
from app.core.database import get_db
from app.core.logging import logger
from app.models.models import SecurityLog, Alert, IncidentCase
from app.models.schemas import BulkLogIngestionRequest, SecurityLogResponse, SecurityLogCreate, LogIngestionResponse
from app.services.parser_service import resolve_geoip, parse_user_agent
from app.services.queue_service import enqueue_logs
from app.services.correlation_engine import correlate_log

router = APIRouter()

@router.get("/stats")
def get_dashboard_stats(interval: str = "5m", db: Session = Depends(get_db)):
    """
    Returns live statistics from the database for the security dashboard.
    """
    try:
        total_events = db.query(SecurityLog).count()
        total_alerts = db.query(Alert).count()
        total_cases = db.query(IncidentCase).count()
        
        # Count critical incidents (Alerts with severity HIGH or CRITICAL)
        critical_incidents = db.query(Alert).filter(Alert.severity.in_(["HIGH", "CRITICAL"])).count()
        
        # Calculate categories count from alerts
        category_counts = db.query(Alert.rule_id, func.count(Alert.id)).group_by(Alert.rule_id).all()
        categories = {
            "Authentication": 0,
            "Web Application": 0,
            "System": 0,
            "Malware": 0,
            "Policy Violation": 0
        }
        for rule_id, count in category_counts:
            if "AUTH" in rule_id:
                categories["Authentication"] += count
            elif "SQL" in rule_id or "XSS" in rule_id:
                categories["Web Application"] += count
            elif "SCAN" in rule_id:
                categories["System"] += count
            elif "MALWARE" in rule_id:
                categories["Malware"] += count
            elif "POLICY" in rule_id:
                categories["Policy Violation"] += count
            else:
                categories["System"] += count

        # Helper to compute count and percentage change vs previous day (48h-24h ago vs 24h-0h ago)
        now = datetime.now()
        last_24h_start = now - timedelta(hours=24)
        prev_24h_start = now - timedelta(hours=48)
        
        def calculate_trend(model, time_field, extra_filter=None):
            # Query last 24h
            q_last = db.query(model).filter(time_field >= last_24h_start)
            if extra_filter is not None:
                q_last = q_last.filter(extra_filter)
            count_last = q_last.count()

            # Query previous 24h
            q_prev = db.query(model).filter(time_field >= prev_24h_start, time_field < last_24h_start)
            if extra_filter is not None:
                q_prev = q_prev.filter(extra_filter)
            count_prev = q_prev.count()

            if count_prev == 0:
                change = 100.0 if count_last > 0 else 0.0
            else:
                change = ((count_last - count_prev) / count_prev) * 100.0

            sign = "+" if change >= 0 else ""
            trend_str = f"{sign}{change:.1f}% vs yesterday"
            is_positive = change >= 0
            return trend_str, is_positive

        events_trend, events_pos = calculate_trend(SecurityLog, SecurityLog.timestamp)
        alerts_trend, alerts_pos = calculate_trend(Alert, Alert.timestamp)
        cases_trend, cases_pos = calculate_trend(IncidentCase, IncidentCase.created_at)
        critical_trend, critical_pos = calculate_trend(Alert, Alert.timestamp, Alert.severity.in_(["HIGH", "CRITICAL"]))

        # Helper to parse timestamps safely
        def parse_ts(ts):
            if not ts:
                return None
            if isinstance(ts, datetime):
                if ts.tzinfo is not None:
                    return ts.replace(tzinfo=None)
                return ts
            if isinstance(ts, str):
                try:
                    clean_str = ts.replace('Z', '').split('+')[0]
                    if '.' in clean_str:
                        dt = datetime.fromisoformat(clean_str)
                    else:
                        dt = datetime.strptime(clean_str, "%Y-%m-%dT%H:%M:%S")
                    if dt.tzinfo is not None:
                        return dt.replace(tzinfo=None)
                    return dt
                except Exception:
                    pass
            return None

        # Generate timeline events based on selected interval (5m, 15m, 30m, 1h)
        minutes_step = 5
        hours_span = 2
        if interval == "15m":
            minutes_step = 15
            hours_span = 6
        elif interval == "30m":
            minutes_step = 30
            hours_span = 12
        elif interval == "1h":
            minutes_step = 60
            hours_span = 24

        timeline = []
        timeline_auth = []
        timeline_firewall = []
        
        cutoff_time = now - timedelta(hours=hours_span)
        # Fetch only active logs and alerts within the window to prevent database bottlenecks
        all_alerts = db.query(Alert).filter(Alert.timestamp >= cutoff_time).all()
        # Fetch logs with a slightly larger window to ensure all alert trigger logs are resolved
        all_logs = db.query(SecurityLog).filter(SecurityLog.timestamp >= (cutoff_time - timedelta(hours=2))).all()
        log_map = {str(log.id): log for log in all_logs if log.id is not None}

        start_times = [now - timedelta(minutes=minutes_step * (23 - i)) for i in range(24)]
        hour_counts = [0] * 24
        hour_auths = [0] * 24
        hour_firewalls = [0] * 24

        hour_alerts = [0] * 24
        hour_auth_alerts = [0] * 24
        hour_firewall_alerts = [0] * 24
        
        # Pre-process all timestamps and assign to buckets in O(M) time
        for log in all_logs:
            log_time = parse_ts(log.timestamp)
            if log_time and log_time >= cutoff_time:
                diff_mins = (log_time - start_times[0]).total_seconds() / 60.0
                if diff_mins >= 0:
                    idx = int(diff_mins // minutes_step)
                    if 0 <= idx < 24:
                        hour_counts[idx] += 1
                        if log.event_type == "auth":
                            hour_auths[idx] += 1
                        elif log.event_type == "firewall":
                            hour_firewalls[idx] += 1
                            
        for alert in all_alerts:
            alert_time = parse_ts(alert.timestamp)
            if alert_time and alert_time >= cutoff_time:
                diff_mins = (alert_time - start_times[0]).total_seconds() / 60.0
                if diff_mins >= 0:
                    idx = int(diff_mins // minutes_step)
                    if 0 <= idx < 24:
                        hour_alerts[idx] += 1
                        t_log = log_map.get(str(alert.trigger_log_id))
                        if t_log:
                            if t_log.event_type == "auth":
                                hour_auth_alerts[idx] += 1
                            elif t_log.event_type == "firewall":
                                hour_firewall_alerts[idx] += 1
                                
        for i in range(24):
            time_str = start_times[i].strftime("%H:%M")
            timeline.append({
                "time": time_str,
                "events": hour_counts[i],
                "alerts": hour_alerts[i]
            })
            timeline_auth.append({
                "time": time_str,
                "events": hour_auths[i],
                "alerts": hour_auth_alerts[i]
            })
            timeline_firewall.append({
                "time": time_str,
                "events": hour_firewalls[i],
                "alerts": hour_firewall_alerts[i]
            })

        # --- Live Threat Intelligence & UEBA Aggregations ---
        import hashlib

        # 1. Threat Sources (Calculated in memory to bypass SQLite date comparison limitations)
        flags = {
            "United States": "🇺🇸", 
            "Canada": "🇨🇦",
            "Netherlands": "🇳🇱", 
            "Russia": "🇷🇺", 
            "Singapore": "🇸🇬", 
            "Brazil": "🇧🇷", 
            "Germany": "🇩🇪", 
            "China": "🇨🇳", 
            "India": "🇮🇳",
            "United Kingdom": "🇬🇧",
            "Unknown Origin": "🌐"
        }

        threat_counts = {}
        threat_max_sev = {}
        
        for log in all_logs:
            log_time = parse_ts(log.timestamp)
            if log_time and log_time >= cutoff_time:
                ip = log.source_ip
                country = log.geo_country
                
                # Exclude local/internal IPs
                if not ip or ip in ("127.0.0.1", "localhost") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                    continue
                cntry = country or "Unknown Origin"
                if cntry in ("Local Network", "Localhost", "Unknown Origin"):
                    continue
                    
                key = (ip, cntry)
                threat_counts[key] = threat_counts.get(key, 0) + 1
                
                sev = log.severity or "INFO"
                current_max = threat_max_sev.get(key, "INFO")
                sev_ranks = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
                if sev_ranks.get(sev, 0) > sev_ranks.get(current_max, 0):
                    threat_max_sev[key] = sev
                    
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:150]
        
        threat_sources = []
        ip_alerts_map = {}
        for alert in all_alerts:
            t_log = log_map.get(str(alert.trigger_log_id))
            if t_log and t_log.source_ip:
                ip_alerts_map.setdefault(t_log.source_ip, []).append(alert)
                
        for (ip, cntry), count in sorted_threats:
            max_sev = threat_max_sev.get((ip, cntry), "INFO")
            alerts_for_ip = ip_alerts_map.get(ip, [])
            alert_count = len(alerts_for_ip)
            alert_sevs = [a.severity for a in alerts_for_ip]
            
            # Determine risk
            if "CRITICAL" in alert_sevs:
                risk = "Critical"
                color = "var(--sev-critical)"
            elif "HIGH" in alert_sevs:
                risk = "High"
                color = "var(--sev-high)"
            elif "MEDIUM" in alert_sevs or alert_count >= 1:
                risk = "Medium"
                color = "var(--sev-medium)"
            else:
                if max_sev in ("ERROR", "CRITICAL"):
                    risk = "Medium"
                    color = "var(--sev-medium)"
                else:
                    risk = "Low"
                    color = "var(--sev-low)"
                    
            threat_sources.append({
                "ip": ip,
                "country": cntry,
                "flag": flags.get(cntry, "🌐"),
                "events": f"{count:,}",
                "risk": risk,
                "color": color
            })

        # 2. Map Hot Spots
        country_coords = {
            "United States": {"cx": 120, "cy": 90},
            "Canada": {"cx": 110, "cy": 60},
            "Netherlands": {"cx": 280, "cy": 75},
            "Germany": {"cx": 270, "cy": 80},
            "United Kingdom": {"cx": 260, "cy": 70},
            "Russia": {"cx": 350, "cy": 68},
            "Singapore": {"cx": 400, "cy": 135},
            "Brazil": {"cx": 195, "cy": 165},
            "China": {"cx": 410, "cy": 100},
            "India": {"cx": 360, "cy": 115}
        }
        
        # Calculate Threat Events Map spots (hot_spots) in memory
        country_max_sev = {}
        for log in all_logs:
            log_time = parse_ts(log.timestamp)
            if log_time and log_time >= cutoff_time and log.geo_country and log.geo_country != "Local Network" and log.source_ip != "127.0.0.1":
                country = log.geo_country
                country_max_sev.setdefault(country, []).append(log.severity)
                
        hot_spots = []
        for country, sevs in country_max_sev.items():
            if country in country_coords:
                coords = country_coords[country]
                max_sev = max(sevs, key=lambda s: {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}.get(s, 0)) if sevs else "INFO"
                risk = "Low"
                color = "hsl(var(--sev-low))"
                if max_sev in ("ERROR", "CRITICAL"):
                    risk = "High" if max_sev == "CRITICAL" else "Medium"
                    color = "hsl(var(--sev-critical))" if max_sev == "CRITICAL" else "hsl(var(--sev-high))"
                elif max_sev == "WARNING":
                    risk = "Medium"
                    color = "hsl(var(--sev-medium))"
                hot_spots.append({
                    "name": country,
                    "cx": coords["cx"],
                    "cy": coords["cy"],
                    "risk": risk,
                    "color": color
                })

        # Calculate Security Alerts Map spots (alert_hot_spots) in memory
        alert_hot_spots = []
        alerts_in_window = []
        for a in all_alerts:
            a_time = parse_ts(a.timestamp)
            if a_time and a_time >= cutoff_time:
                alerts_in_window.append(a)

        alert_log_ids_set = {str(a.trigger_log_id) for a in alerts_in_window if a.trigger_log_id}
        alert_country_groups = {}
        for log in all_logs:
            if str(log.id) in alert_log_ids_set and log.geo_country and log.source_ip != "127.0.0.1":
                log_time = parse_ts(log.timestamp)
                if log_time and log_time >= cutoff_time:
                    country = log.geo_country
                    alert_country_groups.setdefault(country, []).append(log.severity)

        for country, sevs in alert_country_groups.items():
            if country in country_coords:
                coords = country_coords[country]
                max_sev = max(sevs, key=lambda s: {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}.get(s, 0)) if sevs else "INFO"
                risk = "Low"
                color = "hsl(var(--sev-low))"
                if max_sev in ("ERROR", "CRITICAL"):
                    risk = "High" if max_sev == "CRITICAL" else "Medium"
                    color = "hsl(var(--sev-critical))" if max_sev == "CRITICAL" else "hsl(var(--sev-high))"
                elif max_sev == "WARNING":
                    risk = "Medium"
                    color = "hsl(var(--sev-medium))"
                alert_hot_spots.append({
                    "name": country,
                    "cx": coords["cx"],
                    "cy": coords["cy"],
                    "risk": risk,
                    "color": color
                })

        # 3. Targeted Ports (Calculated in memory)
        port_counts = {}
        for log in all_logs:
            log_time = parse_ts(log.timestamp)
            if log_time and log_time >= cutoff_time and log.destination_port and log.destination_port > 0:
                port_counts[log.destination_port] = port_counts.get(log.destination_port, 0) + 1
                
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        port_names = {
            22: "SSH (22)",
            443: "HTTPS (443)",
            80: "HTTP (80)",
            3389: "RDP (3389)",
            21: "FTP (21)"
        }
        targeted_ports = []
        colors = ["#ef4444", "#f59e0b", "#2f80ed", "#a061ff", "#10b981"]
        for i, (port, count) in enumerate(sorted_ports):
            targeted_ports.append({
                "name": port_names.get(port, f"Port {port}"),
                "value": count,
                "color": colors[i % len(colors)]
            })

        # 4. User Risk Profiles
        user_risk_query = db.query(
            SecurityLog.user_id,
            func.count(Alert.id).label("alert_count"),
            func.max(Alert.severity).label("max_severity")
        ).join(
            Alert, Alert.trigger_log_id == SecurityLog.id
        ).filter(
            SecurityLog.user_id != None,
            SecurityLog.user_id != "guest"
        ).group_by(
            SecurityLog.user_id
        ).order_by(
            func.count(Alert.id).desc()
        ).limit(5).all()
        user_risk_profiles = []
        for user_id, alert_count, max_sev in user_risk_query:
            severity = "low"
            status = "Normal Profile"
            risk_score = 10
            if max_sev == "CRITICAL":
                severity = "critical"
                status = "Active Watchlist"
                risk_score = 90 + min(alert_count, 9)
            elif max_sev == "HIGH":
                severity = "high"
                status = "Investigation Pending"
                risk_score = 75 + min(alert_count, 14)
            elif max_sev == "MEDIUM":
                severity = "medium"
                status = "Under Observation"
                risk_score = 45 + min(alert_count, 29)
            elif max_sev == "LOW":
                severity = "low"
                status = "Normal Profile"
                risk_score = 20 + min(alert_count, 24)
            depts = {
                "admin": "IT Systems",
                "root": "Domain Admins",
                "db_admin": "Database Systems",
                "alice.smith": "Developer Operations",
                "john.doe": "Sales & Marketing",
                "bob.johnson": "Human Resources"
            }
            user_risk_profiles.append({
                "id": user_id,
                "department": depts.get(user_id, "General Staff"),
                "riskScore": risk_score,
                "status": status,
                "severity": severity
            })

        # 5. Anomalous Activities
        anomalies_query = db.query(Alert).order_by(Alert.timestamp.desc()).limit(5).all()
        anomalous_activities = []
        for alert in anomalies_query:
            time_diff = "Just now"
            diff = datetime.now() - alert.timestamp
            if diff.total_seconds() < 60:
                time_diff = f"{int(diff.total_seconds())}s ago"
            elif diff.total_seconds() < 3600:
                time_diff = f"{int(diff.total_seconds() / 60)} mins ago"
            else:
                time_diff = f"{int(diff.total_seconds() / 3600)} hours ago"
            trigger_user = alert.trigger_log.user_id if alert.trigger_log else "system"
            anomalous_activities.append({
                "time": time_diff,
                "user": trigger_user or "system",
                "type": alert.title,
                "description": alert.description,
                "risk": alert.severity.upper()
            })

        # 6. Risky Resources
        assets_query = db.query(
            SecurityLog.destination_ip,
            Alert.title,
            func.count(Alert.id).label("alert_count"),
            func.max(Alert.severity).label("max_severity"),
            SecurityLog.user_id
        ).join(
            Alert, Alert.trigger_log_id == SecurityLog.id
        ).group_by(
            SecurityLog.destination_ip,
            Alert.title,
            SecurityLog.user_id
        ).order_by(
            func.count(Alert.id).desc()
        ).limit(5).all()
        risky_resources = []
        for dest_ip, anomaly, count, max_sev, owner in assets_query:
            severity = "low"
            score = 10
            if max_sev == "CRITICAL":
                severity = "critical"
                score = 95
            elif max_sev == "HIGH":
                severity = "high"
                score = 80
            elif max_sev == "MEDIUM":
                severity = "medium"
                score = 50
            risky_resources.append({
                "host": dest_ip or "internal-host.local",
                "anomaly": anomaly,
                "score": score,
                "owner": owner or "system",
                "severity": severity
            })

        # 7. Malicious IOCs
        malicious_iocs = []
        for alert in anomalies_query:
            source_ip = alert.trigger_log.source_ip if alert.trigger_log else None
            h = hashlib.sha256(f"ioc-{alert.id}-{alert.title}".encode()).hexdigest()[:20]
            ioc_pattern = source_ip if "AUTH" in alert.rule_id else f"{h}... (SHA256)"
            ioc_type = "IP Address" if "AUTH" in alert.rule_id else "Malware Hash"
            if "SQL" in alert.rule_id or "XSS" in alert.rule_id:
                ioc_type = "Exploit Payload"
                ioc_pattern = "SQL Injection Payload" if "SQL" in alert.rule_id else "XSS Script Injection"
            malicious_iocs.append({
                "indicator": ioc_pattern,
                "type": ioc_type,
                "score": "95/100" if alert.severity == "CRITICAL" else "85/100" if alert.severity == "HIGH" else "70/100",
                "threat": alert.title,
                "date": alert.timestamp.strftime("%Y-%m-%d")
            })

        # 8. Assets Inventory
        assets_discovery_query = db.query(
            SecurityLog.destination_ip,
            func.count(Alert.id).label("alert_count"),
            func.max(Alert.severity).label("max_severity")
        ).outerjoin(
            Alert, Alert.trigger_log_id == SecurityLog.id
        ).filter(
            SecurityLog.destination_ip != None,
            (SecurityLog.destination_ip.like("10.%") | SecurityLog.destination_ip.like("192.168.%"))
        ).group_by(
            SecurityLog.destination_ip
        ).all()

        hostnames = {
            "10.0.0.15": ("primary-db-srv", "RedHat Enterprise Linux 9.2"),
            "10.0.0.5": ("web-gateway-01", "Ubuntu Server 22.04 LTS"),
            "10.0.0.80": ("sec-auth-ldap", "Debian Bookworm"),
            "10.0.0.100": ("dmz-proxy-ingress", "Alpine Linux (Container)"),
            "10.0.0.2": ("domain-controller-01", "Windows Server 2022")
        }

        assets_list = []
        for dest_ip, alert_count, max_sev in assets_discovery_query:
            hostname, os_name = hostnames.get(dest_ip, (f"discovered-host-{dest_ip.replace('.', '-')}", "Linux Enterprise Kernel"))
            
            vuln_score = min(alert_count * 15, 100)
            if vuln_score == 0:
                vuln_score = 5
                
            severity = "low"
            if max_sev == "CRITICAL" or vuln_score > 75:
                severity = "critical"
            elif max_sev == "HIGH" or vuln_score > 40:
                severity = "high"
            elif max_sev == "MEDIUM" or vuln_score > 20:
                severity = "medium"
                
            assets_list.append({
                "id": hostname,
                "ip": dest_ip,
                "os": os_name,
                "status": "Online",
                "vulnerabilityScore": vuln_score,
                "severity": severity
            })

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "total_cases": total_cases,
            "critical_incidents": critical_incidents,
            "categories": categories,
            "timeline": timeline,
            "timeline_auth": timeline_auth,
            "timeline_firewall": timeline_firewall,
            "events_trend": events_trend,
            "events_is_positive": events_pos,
            "alerts_trend": alerts_trend,
            "alerts_is_positive": alerts_pos,
            "cases_trend": cases_trend,
            "cases_is_positive": cases_pos,
            "critical_trend": critical_trend,
            "critical_is_positive": critical_pos,
            "threat_sources": threat_sources,
            "hot_spots": hot_spots,
            "alert_hot_spots": alert_hot_spots,
            "targeted_ports": targeted_ports,
            "user_risk_profiles": user_risk_profiles,
            "anomalous_activities": anomalous_activities,
            "risky_resources": risky_resources,
            "malicious_iocs": malicious_iocs,
            "assets": assets_list
        }
    except Exception as e:
        logger.error(f"Failed to fetch dashboard stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching dashboard statistics."
        )

@router.post("/ingest", response_model=LogIngestionResponse, status_code=status.HTTP_201_CREATED)
async def ingest_logs(payload: BulkLogIngestionRequest, async_mode: bool = False, db: Session = Depends(get_db)):
    """
    Ingest a batch of structured security logs.
    Supports synchronous DB writes (default) or high-throughput async processing via background queues.
    """
    if async_mode:
        await enqueue_logs(payload.logs)
        return LogIngestionResponse(
            status="queued",
            message="Logs successfully added to processing queue.",
            count=len(payload.logs)
        )

    logger.info(f"Ingesting a batch of {len(payload.logs)} logs (sync)...")
    
    db_logs = []
    try:
        for log_data in payload.logs:
            # Auto-enrich geo location and user agent information
            geo = log_data.geo_country or resolve_geoip(log_data.source_ip)
            ua = parse_user_agent(log_data.user_agent) if log_data.user_agent else "System Agent"
            
            db_log = SecurityLog(
                event_type=log_data.event_type,
                severity=log_data.severity,
                message=log_data.message,
                raw_payload=log_data.raw_payload,
                source_ip=log_data.source_ip,
                destination_ip=log_data.destination_ip,
                source_port=log_data.source_port,
                destination_port=log_data.destination_port,
                geo_country=geo,
                user_agent=ua,
                user_id=log_data.user_id,
                timestamp=log_data.timestamp
            )
            db.add(db_log)
            db_logs.append(db_log)
        
        db.commit()
        
        # Refresh the database records to populate the generated IDs and default values
        for db_log in db_logs:
            db.refresh(db_log)
            # Run correlation checks synchronously
            correlate_log(db_log, db)
            
        logger.info(f"Successfully ingested {len(db_logs)} logs.")
        return LogIngestionResponse(
            status="success",
            message="Logs processed synchronously and persisted to database.",
            count=len(db_logs),
            logs=db_logs
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to ingest logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while saving the logs to the database."
        )

from fastapi.responses import HTMLResponse

@router.get("/map", response_class=HTMLResponse)
def get_interactive_map(db: Session = Depends(get_db)):
    """
    Generates an interactive, zoomable world map using folium.
    Synchronized with the active database threat data.
    """
    try:
        import folium
    except ImportError:
        return HTMLResponse(content="""
        <html>
        <head>
            <style>
                body {
                    background-color: #0f1322;
                    color: #b2bbd6;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    text-align: center;
                }
                .container {
                    padding: 20px;
                    border: 1px dashed rgba(255,255,255,0.1);
                    border-radius: 8px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h3 style="color: #ef4444; margin: 0 0 8px 0;">Python 'folium' Library Missing</h3>
                <p style="margin: 0 0 16px 0; font-size: 0.9rem;">Please run <code>pip install folium</code> in your environment.</p>
                <div style="font-size: 0.75rem; color: #6b7280;">Auto-syncing will resume once installed.</div>
            </div>
        </body>
        </html>
        """, status_code=200)

    # Initialize folium map centered on the world
    # CartoDB Voyager is a premium, highly colorful map style
    m = folium.Map(
        location=[20, 10], 
        zoom_start=1.65, 
        tiles=None, 
        zoom_control=False,
        min_zoom=1.0,
        max_zoom=10,
        control_scale=False
    )
    folium.TileLayer(
        tiles="https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png",
        attr='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        no_wrap=True
    ).add_to(m)

    country_coords = {
        "United States": [37.0902, -95.7129],
        "Canada": [56.1304, -106.3468],
        "Netherlands": [52.1326, 5.2913],
        "Germany": [51.1657, 10.4515],
        "United Kingdom": [55.3781, -3.4360],
        "Russia": [61.5240, 105.3188],
        "Singapore": [1.3521, 103.8198],
        "Brazil": [-14.2350, -51.9253],
        "China": [35.8617, 104.1954],
        "India": [20.5937, 78.9629]
    }

    # All markers are retrieved and drawn dynamically in the client-side JavaScript updateThreatMap loop below.
    # This avoids duplicate markers and ensures instant silent syncing.

    map_html = m.get_root().render()
    
    # Hijack Leaflet map initialization to capture the created map instance immediately
    import re
    leaflet_pattern = r'<script[^>]*src="[^"]*leaflet[^"]*\.js"[^>]*></script>'
    hijack_script = """\\g<0>
<script>
    window.myCapturedMap = null;
    if (typeof L !== 'undefined' && L.Map) {
        L.Map.addInitHook(function() {
            window.myCapturedMap = this;
        });
    }
</script>"""
    map_html = re.sub(leaflet_pattern, hijack_script, map_html, count=1)

    # Inject our custom update script before the closing </body> tag so markers sync silently without reloading the iframe
    injection = """
    <style>
        html, body {
            margin: 0 !important;
            padding: 0 !important;
            width: 100% !important;
            height: 100% !important;
            overflow: hidden !important;
            background-color: #0f1322 !important;
        }
        .folium-map {
            background-color: #0f1322 !important;
            width: 100% !important;
            height: 100% !important;
        }
        #debug-overlay {
            display: none !important;
        }
    </style>
    <div id="debug-overlay" style="position: absolute; bottom: 8px; left: 8px; background: rgba(0,0,0,0.85); color: #00ff00; font-family: monospace; font-size: 9px; padding: 4px 8px; border-radius: 4px; z-index: 10000; pointer-events: none; border: 1px solid #00ff00; line-height: 1.2; display: none;">
        Init...
    </div>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            function setDebug(msg) {
                var el = document.getElementById("debug-overlay");
                if (el) el.innerText = msg;
                console.log("MAP DEBUG:", msg);
            }

            var countryCoords = {
                "United States": [37.0902, -95.7129],
                "Canada": [56.1304, -106.3468],
                "Netherlands": [52.1326, 5.2913],
                "Germany": [51.1657, 10.4515],
                "United Kingdom": [55.3781, -3.4360],
                "Russia": [61.5240, 105.3188],
                "Singapore": [1.3521, 103.8198],
                "Brazil": [-14.2350, -51.9253],
                "China": [35.8617, 104.1954],
                "India": [20.5937, 78.9629]
            };

            var activeMarkers = [];

            function updateThreatMap(mapObj, data, mapView) {
                if (!data) {
                    setDebug("Update call: empty data");
                    return;
                }
                
                // Clear existing markers
                activeMarkers.forEach(function(m) { mapObj.removeLayer(m); });
                activeMarkers = [];

                var view = mapView || window.lastReceivedMapView || 'events';
                var spots = view === 'alerts' ? data.alert_hot_spots : data.hot_spots;
                if (!spots) spots = [];

                var dotsCount = 0;
                if (data) {
                    spots.forEach(function(spot) {
                        var coord = countryCoords[spot.name];
                        if (coord) {
                            dotsCount++;
                            var color = "#10b981"; // Low (Green)
                            if (spot.color.indexOf("critical") !== -1) {
                                color = "#ef4444"; // Critical (Red)
                            } else if (spot.color.indexOf("high") !== -1) {
                                color = "#f97316"; // High (Orange)
                            } else if (spot.color.indexOf("medium") !== -1) {
                                color = "#f59e0b"; // Medium (Amber)
                            }

                            var eventsText = "0";
                            if (data.threat_sources) {
                                for (var i = 0; i < data.threat_sources.length; i++) {
                                    if (data.threat_sources[i].country === spot.name) {
                                        eventsText = data.threat_sources[i].events;
                                        break;
                                    }
                                }
                            }
                            var cleanCount = parseInt(eventsText.replace(/,/g, "")) || 10;

                            var radius_px = Math.min(Math.max(8 + Math.pow(cleanCount, 0.3) * 1.5, 10), 26);
                            var pulse_size = radius_px * 3.2;

                            var marker_html = 
                                '<div style="position: relative; width: ' + pulse_size + 'px; height: ' + pulse_size + 'px; display: flex; align-items: center; justify-content: center; margin-left: -' + (pulse_size/2) + 'px; margin-top: -' + (pulse_size/2) + 'px;">' +
                                    '<div style="' +
                                        'position: absolute;' +
                                        'width: ' + radius_px + 'px;' +
                                        'height: ' + radius_px + 'px;' +
                                        'border-radius: 50%;' +
                                        'background-color: ' + color + ';' +
                                        'box-shadow: 0 0 8px rgba(0,0,0,0.5);' +
                                        'z-index: 2;' +
                                    '"></div>' +
                                    '<div class="breathing-ring" style="' +
                                        'position: absolute;' +
                                        'width: ' + radius_px + 'px;' +
                                        'height: ' + radius_px + 'px;' +
                                        'border-radius: 50%;' +
                                        'background-color: ' + color + ';' +
                                        'animation: pulse-breathing-effect 1.8s cubic-bezier(0.25, 0.46, 0.45, 0.94) infinite;' +
                                        'z-index: 1;' +
                                    '"></div>' +
                                '</div>' +
                                '<style>' +
                                '@keyframes pulse-breathing-effect {' +
                                    '0% {' +
                                        'transform: scale(0.6);' +
                                        'opacity: 0.9;' +
                                    '}' +
                                    '100% {' +
                                        'transform: scale(3.2);' +
                                        'opacity: 0;' +
                                    '}' +
                                '}' +
                                '</style>';

                            var popup_html = 
                                '<div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 11px; padding: 4px; min-width: 120px; line-height: 1.4; color: #111827;">' +
                                    '<h4 style="margin: 0 0 6px 0; font-weight: 700; color: ' + color + '; font-size: 12px; border-bottom: 1px solid #eee; padding-bottom: 4px;">' + spot.name + '</h4>' +
                                    '<div style="display: flex; justify-content: space-between; margin-bottom: 2px;">' +
                                        '<span style="color: #6b7280;">Threat Level:</span>' + 
                                        '<span style="font-weight: 600; color: ' + color + ';">' + spot.risk + '</span>' +
                                    '</div>' +
                                    '<div style="display: flex; justify-content: space-between; margin-bottom: 2px;">' +
                                        '<span style="color: #6b7280;">Events:</span>' + 
                                        '<span style="font-weight: 600; color: #111827;">' + eventsText + '</span>' +
                                    '</div>' +
                                '</div>';

                            var marker = L.marker(coord, {
                                icon: L.divIcon({
                                    html: marker_html,
                                    className: '',
                                    iconSize: [pulse_size, pulse_size],
                                    iconAnchor: [pulse_size / 2, pulse_size / 2]
                                })
                            }).bindPopup(popup_html, { maxWidth: 200 });

                            marker.addTo(mapObj);
                            activeMarkers.push(marker);
                        }
                    });
                }
                var spotsList = view === 'alerts' ? (data.alert_hot_spots || []) : (data.hot_spots || []);
                setDebug("Drawn: " + dotsCount + " dots (total hot spots in data: " + spotsList.length + ", view: " + view + ")");
            }

            function fetchStatsFallback(mapObj) {
                setDebug("Fetch fallback started...");
                fetch("/api/v1/logs/stats")
                    .then(function(res) { return res.json(); })
                    .then(function(data) {
                        setDebug("Fetch fallback success");
                        updateThreatMap(mapObj, data, window.lastReceivedMapView);
                    })
                    .catch(function(err) {
                        setDebug("Fetch fallback error: " + err.message);
                    });
            }

            window.lastReceivedStats = null;
            window.lastReceivedMapView = 'events';
            window.myCapturedMapInstance = null;

            // Register window postMessage listener immediately to catch early stats updates
            window.addEventListener("message", function(event) {
                var msg = event.data;
                if (msg && msg.type === "siem-stats-update") {
                    window.lastReceivedStats = msg.stats;
                    window.lastReceivedMapView = msg.mapView || 'events';
                    var spotsList = window.lastReceivedMapView === 'alerts' ? (msg.stats && msg.stats.alert_hot_spots ? msg.stats.alert_hot_spots.length : 0) : (msg.stats && msg.stats.hot_spots ? msg.stats.hot_spots.length : 0);
                    setDebug("Received postMessage, spots: " + spotsList + ", view: " + window.lastReceivedMapView);
                    if (window.myCapturedMapInstance) {
                        updateThreatMap(window.myCapturedMapInstance, msg.stats, window.lastReceivedMapView);
                    } else {
                        setDebug("Received postMessage, but myCapturedMapInstance is not ready");
                    }
                }
            });

            function initWhenMapReady() {
                var mapObj = window.myCapturedMap || null;
                if (!mapObj) {
                    setDebug("Waiting for myCapturedMap...");
                    setTimeout(initWhenMapReady, 20);
                    return;
                }

                setDebug("Map Captured! Initializing...");
                window.myCapturedMapInstance = mapObj;

                // Lock zooming of the map completely but allow dragging/panning
                mapObj.touchZoom.disable();
                mapObj.doubleClickZoom.disable();
                mapObj.scrollWheelZoom.disable();
                mapObj.boxZoom.disable();
                if (mapObj.zoomControl) {
                    mapObj.zoomControl.remove();
                }

                // Immediately draw stats if we received them during initialization
                if (window.lastReceivedStats) {
                    setDebug("Drawing cached stats...");
                    updateThreatMap(mapObj, window.lastReceivedStats, window.lastReceivedMapView);
                } else {
                    // Run initial fallback fetch
                    fetchStatsFallback(mapObj);
                }
            }

            initWhenMapReady();
        });
    </script>
    </body>
    """
    print("=================== /MAP ENDPOINT CALLED ===================")
    print("map_html length:", len(map_html))
    leaflet_pattern = r'<script[^>]*src="[^"]*leaflet[^"]*\.js"[^>]*></script>'
    matches = re.findall(leaflet_pattern, map_html)
    print("Leaflet pattern matches count:", len(matches))
    for m_val in matches:
        print("MATCH:", m_val)
    
    test_sub = re.sub(leaflet_pattern, "HIJACKED_LEAFLET", map_html, count=1)
    if "HIJACKED_LEAFLET" in test_sub:
        print("Leaflet replace: SUCCESS")
    else:
        print("Leaflet replace: FAILED")

    body_pattern = r'(?i)</body>'
    map_html = re.sub(body_pattern, injection + "\n</body>", map_html, count=1)
    if "debug-overlay" in map_html:
        print(">>> SUCCESS: debug-overlay is present in final map HTML")
    else:
        print(">>> WARNING: debug-overlay is MISSING from final map HTML")
    print("============================================================")

    response = HTMLResponse(content=map_html, status_code=200)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

