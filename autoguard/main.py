from collections import defaultdict
from decimal import Decimal
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import current_user, login_required
from .extensions import db
from .models import User, Vehicle, MaintenanceRecord, LoginAttempt
from .forms import ProfileForm
from .security import active_required, admin_required, audit

bp = Blueprint('main', __name__)


def own_records():
    return db.session.scalars(db.select(MaintenanceRecord).join(Vehicle).where(Vehicle.user_id == current_user.id).order_by(MaintenanceRecord.date.desc(), MaintenanceRecord.id.desc())).all()


@bp.get('/')
def home():
    return render_template('home.html')


@bp.get('/dashboard')
@active_required
def dashboard():
    vehicles = db.session.scalars(db.select(Vehicle).where(Vehicle.user_id == current_user.id)).all()
    records = own_records()
    return render_template('dashboard.html', vehicles=vehicles, records=records[:5], count=len(records), total=sum((r.cost for r in records), Decimal(0)))


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.name = form.name.data.strip()
        db.session.commit()
        flash('Профіль оновлено.', 'success')
        return redirect(url_for('main.profile'))
    return render_template('profile.html', form=form)


@bp.get('/history')
@active_required
def history():
    return render_template('history.html', records=own_records())


@bp.get('/statistics')
@active_required
def statistics():
    records = own_records()
    months, cars = defaultdict(Decimal), defaultdict(Decimal)
    for record in records:
        months[record.date.strftime('%Y-%m')] += record.cost
        cars[f'{record.vehicle.make} {record.vehicle.model} · #{record.vehicle.id}'] += record.cost
    maximum = max(months.values(), default=Decimal(1)) or Decimal(1)
    return render_template('statistics.html', total=sum((r.cost for r in records), Decimal(0)), count=len(records), months=sorted(months.items()), cars=cars, maximum=maximum)


@bp.get('/logins')
@active_required
def logins():
    attempts = db.session.scalars(db.select(LoginAttempt).where(LoginAttempt.user_id == current_user.id).order_by(LoginAttempt.id.desc()).limit(100)).all()
    return render_template('logins.html', attempts=attempts, admin=False)


@bp.get('/admin')
@admin_required
def admin():
    query = db.select(User)
    search = request.args.get('q', '').strip()[:100]
    if search:
        query = query.where(db.or_(User.email.contains(search, autoescape=True), User.name.contains(search, autoescape=True)))
    users = db.session.scalars(query.order_by(User.id.desc()).limit(200)).all()
    failures = dict(db.session.execute(db.select(LoginAttempt.user_id, db.func.count(LoginAttempt.id)).where(LoginAttempt.success.is_(False)).group_by(LoginAttempt.user_id)).all())
    return render_template('admin.html', users=users, search=search, failures=failures)


@bp.post('/admin/users/<int:user_id>/toggle')
@admin_required
def toggle(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id or user.role == 'ADMIN':
        abort(403)
    user.blocked = not user.blocked
    user.session_version += 1
    db.session.commit()
    # A new event resets lockout on unlock without rewriting historical failures.
    audit(user.email, True, user, 'account_blocked' if user.blocked else 'account_unblocked')
    flash('Статус користувача оновлено.', 'success')
    return redirect(url_for('main.admin'))


@bp.get('/admin/logins')
@admin_required
def admin_logins():
    attempts = db.session.scalars(db.select(LoginAttempt).order_by(LoginAttempt.id.desc()).limit(200)).all()
    return render_template('logins.html', attempts=attempts, admin=True)
