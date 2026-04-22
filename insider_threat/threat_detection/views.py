import csv
from django.http import HttpResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from datetime import datetime
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Count
from .models import NetworkLog, Alert
from .serializers import NetworkLogSerializer, AlertSerializer
from .tasks import run_anomaly_detection
from django.http import JsonResponse
from .models import NetworkLog, Alert, LoginAuditLog

@login_required
def alert_count_api(request):
    count = Alert.objects.filter(is_resolved=False).count()
    return JsonResponse({'unresolved': count})


# ─────────────────────────────────────────
#  AUTH VIEWS
# ─────────────────────────────────────────

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        # Get real IP
        ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() \
             or request.META.get('REMOTE_ADDR')

        if user is not None:
            login(request, user)
            LoginAuditLog.objects.create(
                username=username,
                ip_address=ip,
                success=True,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            return redirect('dashboard')
        else:
            LoginAuditLog.objects.create(
                username=username,
                ip_address=ip,
                success=False,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            return render(request, 'login.html', {'error': 'Invalid credentials'})

    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('login')


# ─────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────

@login_required
def dashboard(request):
    total_logs = NetworkLog.objects.count()
    anomalous_logs = NetworkLog.objects.filter(is_anomalous=True).count()
    total_alerts = Alert.objects.count()
    unresolved_alerts = Alert.objects.filter(is_resolved=False).count()

    severity_data = Alert.objects.values('severity').annotate(count=Count('severity'))

    top_ips = (
        NetworkLog.objects.filter(is_anomalous=True)
        .values('source_ip')
        .annotate(count=Count('source_ip'))
        .order_by('-count')[:5]
    )

    attack_data = (
        NetworkLog.objects.exclude(attack_type='')
        .values('attack_type')
        .annotate(count=Count('attack_type'))
        .order_by('-count')[:6]
    )

    recent_alerts = Alert.objects.filter(
        is_resolved=False
    ).order_by('-created_at')[:10]

    context = {
        'total_logs': total_logs,
        'anomalous_logs': anomalous_logs,
        'total_alerts': total_alerts,
        'unresolved_alerts': unresolved_alerts,
        'severity_data': list(severity_data),
        'top_ips': list(top_ips),
        'attack_data': list(attack_data),
        'recent_alerts': recent_alerts,
        'user': request.user,
    }
    return render(request, 'dashboard.html', context)


# ─────────────────────────────────────────
#  ALERTS PAGE
# ─────────────────────────────────────────

@login_required
def alerts_page(request):
    severity_filter = request.GET.get('severity', '')
    status_filter   = request.GET.get('status', '')
    search_query    = request.GET.get('q', '')

    alerts = Alert.objects.select_related('log').order_by('-created_at')

    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    if status_filter == 'resolved':
        alerts = alerts.filter(is_resolved=True)
    elif status_filter == 'unresolved':
        alerts = alerts.filter(is_resolved=False)
    if search_query:
        alerts = alerts.filter(message__icontains=search_query)

    # Handle resolve action
    if request.method == 'POST':
        alert_id = request.POST.get('alert_id')
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.is_resolved = True
            alert.save()
            messages.success(request, f'Alert #{alert_id} marked as resolved.')
        except Alert.DoesNotExist:
            messages.error(request, 'Alert not found.')
        return redirect('alerts')

    context = {
        'alerts':          alerts[:100],
        'severity_filter': severity_filter,
        'status_filter':   status_filter,
        'search_query':    search_query,
        'total':           alerts.count(),
        'user':            request.user,
    }
    return render(request, 'alerts.html', context)

# ─────────────────────────────────────────
#  USERS PAGE
# ─────────────────────────────────────────

@login_required
@login_required
def users_page(request):
    if not request.user.is_superuser:
        return redirect('dashboard')

    # existing user logic...
    all_users = User.objects.all()
    audit_logs = LoginAuditLog.objects.all()[:50]

    return render(request, 'users.html', {
        'users': all_users,
        'audit_logs': audit_logs,
    })

    if request.method == 'POST':
        action_type = request.POST.get('action')

        if action_type == 'create':
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            role = request.POST.get('role', 'analyst')
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists.')
            else:
                new_user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                if role == 'admin':
                    new_user.is_staff = True
                    new_user.is_superuser = True
                new_user.save()
                messages.success(request, f'User {username} created successfully.')

        elif action_type == 'toggle':
            user_id = request.POST.get('user_id')
            try:
                target = User.objects.get(id=user_id)
                if target != request.user:
                    target.is_active = not target.is_active
                    target.save()
                    status = 'enabled' if target.is_active else 'disabled'
                    messages.success(request, f'User {target.username} {status}.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')

        elif action_type == 'delete':
            user_id = request.POST.get('user_id')
            try:
                target = User.objects.get(id=user_id)
                if target != request.user:
                    target.delete()
                    messages.success(request, 'User deleted.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')

        return redirect('users')

    context = {
        'users': users,
        'user': request.user,
    }
    return render(request, 'users.html', context)


# ─────────────────────────────────────────
#  REPORTS PAGE
# ─────────────────────────────────────────

@login_required
def reports_page(request):
    total_logs = NetworkLog.objects.count()
    anomalous_logs = NetworkLog.objects.filter(is_anomalous=True).count()
    total_alerts = Alert.objects.count()
    resolved_alerts = Alert.objects.filter(is_resolved=True).count()
    unresolved_alerts = Alert.objects.filter(is_resolved=False).count()

    severity_data = Alert.objects.values('severity').annotate(
        count=Count('severity')
    ).order_by('-count')

    attack_data = (
        NetworkLog.objects.exclude(attack_type='')
        .values('attack_type')
        .annotate(count=Count('attack_type'))
        .order_by('-count')
    )

    top_users = (
        NetworkLog.objects.filter(is_anomalous=True)
        .exclude(user_information='')
        .values('user_information')
        .annotate(count=Count('user_information'))
        .order_by('-count')[:10]
    )

    context = {
        'total_logs': total_logs,
        'anomalous_logs': anomalous_logs,
        'total_alerts': total_alerts,
        'resolved_alerts': resolved_alerts,
        'unresolved_alerts': unresolved_alerts,
        'severity_data': severity_data,
        'attack_data': attack_data,
        'top_users': top_users,
        'user': request.user,
    }
    return render(request, 'reports.html', context)

# ─────────────────────────────────────────
#  NETWORK LOGS PAGE
# ─────────────────────────────────────────

@login_required
def logs_page(request):
    search = request.GET.get('search', '')
    protocol = request.GET.get('protocol', '')
    anomalous = request.GET.get('anomalous', '')

    logs = NetworkLog.objects.all().order_by('-timestamp')

    if search:
        logs = logs.filter(source_ip__icontains=search) | \
               logs.filter(destination_ip__icontains=search) | \
               logs.filter(user_information__icontains=search)

    if protocol:
        logs = logs.filter(protocol=protocol)

    if anomalous == 'true':
        logs = logs.filter(is_anomalous=True)
    elif anomalous == 'false':
        logs = logs.filter(is_anomalous=False)

    total = logs.count()
    logs = logs[:200]

    protocols = NetworkLog.objects.values_list(
        'protocol', flat=True
    ).distinct()

    context = {
        'logs': logs,
        'total': total,
        'search': search,
        'protocol': protocol,
        'anomalous': anomalous,
        'protocols': protocols,
        'user': request.user,
    }
    return render(request, 'logs.html', context)


# ─────────────────────────────────────────
#  USER RISK SCORING PAGE
# ─────────────────────────────────────────

@login_required
def risk_page(request):
    # Score each user by anomaly count
    user_risk = (
        NetworkLog.objects.filter(is_anomalous=True)
        .exclude(user_information='')
        .values('user_information')
        .annotate(
            anomaly_count=Count('user_information'),
            attack_types=Count('attack_type', distinct=True),
        )
        .order_by('-anomaly_count')[:50]
    )

    # Add risk level label
    scored_users = []
    for u in user_risk:
        count = u['anomaly_count']
        if count >= 10:
            level = 'Critical'
        elif count >= 6:
            level = 'High'
        elif count >= 3:
            level = 'Medium'
        else:
            level = 'Low'
        scored_users.append({
            'name': u['user_information'],
            'count': count,
            'attack_types': u['attack_types'],
            'level': level,
        })

    # Summary counts
    critical = sum(1 for u in scored_users if u['level'] == 'Critical')
    high     = sum(1 for u in scored_users if u['level'] == 'High')
    medium   = sum(1 for u in scored_users if u['level'] == 'Medium')
    low      = sum(1 for u in scored_users if u['level'] == 'Low')

    context = {
        'scored_users': scored_users,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'user': request.user,
    }
    return render(request, 'risk.html', context)

    # ─────────────────────────────────────────
#  PDF REPORT EXPORT
# ─────────────────────────────────────────

@login_required
def export_pdf(request):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="sentineliq_report.pdf"'

    doc = SimpleDocTemplate(response, pagesize=A4,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)
    elements = []
    styles = getSampleStyleSheet()

    # Title style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=22,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=20,
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=16,
        spaceAfter=8,
        borderPad=4,
    )

    # Header
    elements.append(Paragraph("SentinelIQ — Threat Detection Report", title_style))
    elements.append(Paragraph(
        f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')} | By {request.user.username}",
        subtitle_style
    ))

    # Divider
    elements.append(Table(
        [['']],
        colWidths=[7.2 * inch],
        style=TableStyle([('LINEBELOW', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0'))])
    ))
    elements.append(Spacer(1, 12))

    # Summary stats
    total_logs = NetworkLog.objects.count()
    anomalous = NetworkLog.objects.filter(is_anomalous=True).count()
    total_alerts = Alert.objects.count()
    resolved = Alert.objects.filter(is_resolved=True).count()
    unresolved = Alert.objects.filter(is_resolved=False).count()

    elements.append(Paragraph("Executive Summary", section_style))
    summary_data = [
        ['Metric', 'Value'],
        ['Total Network Logs Analysed', f'{total_logs:,}'],
        ['Anomalies Detected by ML Model', f'{anomalous:,}'],
        ['Anomaly Rate', f'{(anomalous/total_logs*100):.1f}%' if total_logs else '0%'],
        ['Total Alerts Generated', f'{total_alerts:,}'],
        ['Resolved Alerts', f'{resolved:,}'],
        ['Unresolved Alerts', f'{unresolved:,}'],
    ]
    summary_table = Table(summary_data, colWidths=[3.5*inch, 3.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,0),  colors.HexColor('#1e40af')),
        ('TEXTCOLOR',   (0,0), (-1,0),  colors.white),
        ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,0),  10),
        ('FONTSIZE',    (0,1), (-1,-1), 9),
        ('BACKGROUND',  (0,1), (-1,-1), colors.HexColor('#f8fafc')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING',     (0,0), (-1,-1), 8),
        ('FONTNAME',    (0,1), (0,-1),  'Helvetica-Bold'),
        ('TEXTCOLOR',   (0,1), (0,-1),  colors.HexColor('#374151')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Alerts by severity
    elements.append(Paragraph("Alerts by Severity", section_style))
    severity_data = list(
        Alert.objects.values('severity')
        .annotate(count=Count('severity'))
        .order_by('-count')
    )
    sev_table_data = [['Severity Level', 'Alert Count', 'Percentage']]
    for s in severity_data:
        pct = f"{(s['count']/total_alerts*100):.1f}%" if total_alerts else '0%'
        sev_table_data.append([s['severity'], str(s['count']), pct])

    sev_colors = {
        'Critical': colors.HexColor('#7c3aed'),
        'High':     colors.HexColor('#dc2626'),
        'Medium':   colors.HexColor('#d97706'),
        'Low':      colors.HexColor('#16a34a'),
    }
    sev_table = Table(sev_table_data, colWidths=[2.4*inch, 2.4*inch, 2.4*inch])
    sev_style = [
        ('BACKGROUND', (0,0), (-1,0),  colors.HexColor('#1e40af')),
        ('TEXTCOLOR',  (0,0), (-1,0),  colors.white),
        ('FONTNAME',   (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING',    (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f8fafc'), colors.white]),
    ]
    for i, s in enumerate(severity_data, start=1):
        c = sev_colors.get(s['severity'], colors.HexColor('#374151'))
        sev_style.append(('TEXTCOLOR', (0,i), (0,i), c))
        sev_style.append(('FONTNAME',  (0,i), (0,i), 'Helvetica-Bold'))
    sev_table.setStyle(TableStyle(sev_style))
    elements.append(sev_table)
    elements.append(Spacer(1, 12))

    # Attack type breakdown
    elements.append(Paragraph("Attack Type Breakdown", section_style))
    attack_data = list(
        NetworkLog.objects.exclude(attack_type='')
        .values('attack_type')
        .annotate(count=Count('attack_type'))
        .order_by('-count')
    )
    atk_data = [['Attack Type', 'Occurrences', 'Percentage']]
    total_atk = sum(a['count'] for a in attack_data)
    for a in attack_data:
        pct = f"{(a['count']/total_atk*100):.1f}%" if total_atk else '0%'
        atk_data.append([a['attack_type'], f"{a['count']:,}", pct])

    atk_table = Table(atk_data, colWidths=[2.4*inch, 2.4*inch, 2.4*inch])
    atk_table.setStyle(TableStyle([
        ('BACKGROUND',     (0,0), (-1,0),  colors.HexColor('#1e40af')),
        ('TEXTCOLOR',      (0,0), (-1,0),  colors.white),
        ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',       (0,0), (-1,-1), 9),
        ('GRID',           (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING',        (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f8fafc'), colors.white]),
    ]))
    elements.append(atk_table)
    elements.append(Spacer(1, 12))

    # Top 10 risky users
    elements.append(Paragraph("Top 10 High-Risk Users", section_style))
    top_users = list(
        NetworkLog.objects.filter(is_anomalous=True)
        .exclude(user_information='')
        .values('user_information')
        .annotate(count=Count('user_information'))
        .order_by('-count')[:10]
    )
    user_data = [['Rank', 'User', 'Anomaly Count', 'Risk Level']]
    for i, u in enumerate(top_users, 1):
        if u['count'] >= 10:   level = 'Critical'
        elif u['count'] >= 6:  level = 'High'
        elif u['count'] >= 3:  level = 'Medium'
        else:                  level = 'Low'
        user_data.append([str(i), u['user_information'], str(u['count']), level])

    user_table = Table(user_data, colWidths=[0.6*inch, 3*inch, 1.8*inch, 1.8*inch])
    user_table.setStyle(TableStyle([
        ('BACKGROUND',     (0,0), (-1,0),  colors.HexColor('#1e40af')),
        ('TEXTCOLOR',      (0,0), (-1,0),  colors.white),
        ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',       (0,0), (-1,-1), 9),
        ('GRID',           (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING',        (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f8fafc'), colors.white]),
    ]))
    elements.append(user_table)

    # Footer
    elements.append(Spacer(1, 24))
    elements.append(Table(
        [['']],
        colWidths=[7.2*inch],
        style=TableStyle([('LINEABOVE', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0'))])
    ))
    elements.append(Paragraph(
        "SentinelIQ — Confidential Security Report | For Internal Use Only",
        ParagraphStyle('Footer', parent=styles['Normal'],
                       fontSize=8, textColor=colors.HexColor('#94a3b8'),
                       alignment=1, spaceBefore=8)
    ))

    doc.build(elements)
    return response


# ─────────────────────────────────────────
#  CSV EXPORT
# ─────────────────────────────────────────

@login_required
def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="sentineliq_anomalous_logs.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'Timestamp', 'Source IP', 'Destination IP',
        'Protocol', 'Packet Length', 'Attack Type',
        'Severity Level', 'User', 'Network Segment',
        'Anomaly Score', 'Is Anomalous'
    ])

    logs = NetworkLog.objects.filter(
        is_anomalous=True
    ).order_by('-timestamp')[:5000]

    for log in logs:
        writer.writerow([
            log.timestamp,
            log.source_ip,
            log.destination_ip,
            log.protocol,
            log.packet_length,
            log.attack_type,
            log.severity_level,
            log.user_information,
            log.network_segment,
            log.anomaly_score,
            log.is_anomalous,
        ])

    return response

# ─────────────────────────────────────────
#  BLOCKCHAIN VERIFICATION PAGE
# ─────────────────────────────────────────

@login_required
def blockchain_page(request):
    from .blockchain import verify_chain, build_hash_chain

    message = None
    verified_count = 0
    tampered_count = 0

    # Build chain action
    if request.method == 'POST' and request.POST.get('action') == 'build':
        logs = NetworkLog.objects.all().order_by('id')
        total = build_hash_chain(logs)
        messages.success(request, f'Hash chain built for {total} logs successfully!')
        return redirect('blockchain')

    # Get last 50 logs for display
    logs = NetworkLog.objects.exclude(
        log_hash=''
    ).order_by('id')

    total_hashed = logs.count()

    # Verify last 20 for display
    sample = list(logs[:20])
    from .blockchain import verify_chain
    results = verify_chain(sample) if sample else []

    verified_count = sum(1 for r in results if r['is_valid'])
    tampered_count = sum(1 for r in results if not r['is_valid'])

    # Chain stats
    total_logs = NetworkLog.objects.count()
    hashed_logs = NetworkLog.objects.exclude(log_hash='').count()

    context = {
        'results': results,
        'verified_count': verified_count,
        'tampered_count': tampered_count,
        'total_logs': total_logs,
        'hashed_logs': hashed_logs,
        'chain_complete': total_logs == hashed_logs,
        'user': request.user,
    }
    return render(request, 'blockchain.html', context)


# ─────────────────────────────────────────
#  API VIEWSETS
# ─────────────────────────────────────────

class NetworkLogViewSet(viewsets.ModelViewSet):
    queryset = NetworkLog.objects.all()
    serializer_class = NetworkLogSerializer

    def get_queryset(self):
        queryset = NetworkLog.objects.all()
        is_anomalous = self.request.query_params.get('is_anomalous')
        attack_type = self.request.query_params.get('attack_type')
        severity = self.request.query_params.get('severity_level')
        if is_anomalous is not None:
            queryset = queryset.filter(
                is_anomalous=is_anomalous.lower() == 'true'
            )
        if attack_type:
            queryset = queryset.filter(attack_type__icontains=attack_type)
        if severity:
            queryset = queryset.filter(severity_level=severity)
        return queryset

    @action(detail=False, methods=['post'])
    def run_ml(self, request):
        result = run_anomaly_detection()
        return Response({'message': result})


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer

    def get_queryset(self):
        queryset = Alert.objects.all()
        is_resolved = self.request.query_params.get('is_resolved')
        severity = self.request.query_params.get('severity')
        if is_resolved is not None:
            queryset = queryset.filter(
                is_resolved=is_resolved.lower() == 'true'
            )
        if severity:
            queryset = queryset.filter(severity=severity)
        return queryset

@login_required
def trigger_demo_alert(request):
    import random
    if request.method == 'POST':
        log = NetworkLog.objects.filter(
            is_anomalous=True
        ).order_by('?').first()
        if log:
            Alert.objects.create(
                log=log,
                message=f"LIVE DETECTION: Anomalous behaviour from {log.source_ip} — "
                        f"User {log.user_information} triggered {log.attack_type} pattern",
                severity=random.choice(['High', 'Critical']),
                is_resolved=False
            )
            messages.success(
                request,
                f'New threat alert generated for {log.source_ip}'
            )
    return redirect('dashboard')