from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import current_user
from .extensions import db
from .models import Vehicle, MaintenanceRecord
from .forms import VehicleForm, MaintenanceForm
from .security import active_required

bp = Blueprint('garage', __name__, url_prefix='/garage')


def owned_vehicle(vehicle_id):
    return db.first_or_404(db.select(Vehicle).where(Vehicle.id == vehicle_id, Vehicle.user_id == current_user.id))


@bp.get('/')
@active_required
def index():
    vehicles = db.session.scalars(db.select(Vehicle).where(Vehicle.user_id == current_user.id).order_by(Vehicle.id.desc())).all()
    return render_template('garage.html', vehicles=vehicles)


@bp.route('/new', methods=['GET', 'POST'])
@active_required
def new():
    form = VehicleForm()
    if form.validate_on_submit():
        vehicle = Vehicle(user_id=current_user.id)
        for key in ('make', 'model', 'year', 'engine', 'mileage', 'vin'):
            setattr(vehicle, key, getattr(form, key).data)
        db.session.add(vehicle)
        db.session.commit()
        flash('Автомобіль додано до гаража.', 'success')
        return redirect(url_for('garage.index'))
    return render_template('form.html', form=form, title='Додати автомобіль', subtitle='Збережіть головне про ваше авто.', wide=True)


@bp.route('/<int:vehicle_id>/edit', methods=['GET', 'POST'])
@active_required
def edit(vehicle_id):
    vehicle = owned_vehicle(vehicle_id)
    form = VehicleForm(obj=vehicle)
    if form.validate_on_submit():
        for key in ('make', 'model', 'year', 'engine', 'mileage', 'vin'):
            setattr(vehicle, key, getattr(form, key).data)
        db.session.commit()
        flash('Дані автомобіля оновлено.', 'success')
        return redirect(url_for('garage.detail', vehicle_id=vehicle.id))
    return render_template('form.html', form=form, title='Редагувати автомобіль', subtitle=f'{vehicle.make} {vehicle.model}', wide=True)


@bp.post('/<int:vehicle_id>/delete')
@active_required
def delete(vehicle_id):
    db.session.delete(owned_vehicle(vehicle_id))
    db.session.commit()
    flash('Автомобіль та його записи видалено.', 'success')
    return redirect(url_for('garage.index'))


@bp.route('/<int:vehicle_id>', methods=['GET', 'POST'])
@active_required
def detail(vehicle_id):
    vehicle = owned_vehicle(vehicle_id)
    form = MaintenanceForm()
    if form.validate_on_submit():
        record = MaintenanceRecord(vehicle_id=vehicle.id)
        for key in ('date', 'work', 'mileage', 'cost', 'notes'):
            setattr(record, key, getattr(form, key).data)
        vehicle.mileage = max(vehicle.mileage, record.mileage)
        db.session.add(record)
        db.session.commit()
        flash('Обслуговування записано.', 'success')
        return redirect(url_for('garage.detail', vehicle_id=vehicle.id))
    records = db.session.scalars(db.select(MaintenanceRecord).where(MaintenanceRecord.vehicle_id == vehicle.id).order_by(MaintenanceRecord.date.desc(), MaintenanceRecord.id.desc())).all()
    return render_template('vehicle.html', vehicle=vehicle, records=records, form=form)


@bp.post('/records/<int:record_id>/delete')
@active_required
def delete_record(record_id):
    record = db.first_or_404(db.select(MaintenanceRecord).join(Vehicle).where(MaintenanceRecord.id == record_id, Vehicle.user_id == current_user.id))
    vehicle_id = record.vehicle_id
    db.session.delete(record)
    db.session.commit()
    flash('Запис видалено.', 'success')
    return redirect(url_for('garage.detail', vehicle_id=vehicle_id))


@bp.route('/records/<int:record_id>/edit', methods=['GET', 'POST'])
@active_required
def edit_record(record_id):
    record = db.first_or_404(db.select(MaintenanceRecord).join(Vehicle).where(
        MaintenanceRecord.id == record_id, Vehicle.user_id == current_user.id))
    form = MaintenanceForm(obj=record)
    if form.validate_on_submit():
        for key in ('date', 'work', 'mileage', 'cost', 'notes'):
            setattr(record, key, getattr(form, key).data)
        record.vehicle.mileage = max(record.vehicle.mileage, record.mileage)
        db.session.commit()
        flash('Запис обслуговування оновлено.', 'success')
        return redirect(url_for('garage.detail', vehicle_id=record.vehicle_id))
    return render_template('form.html', form=form, title='Редагувати обслуговування',
                           subtitle=f'{record.vehicle.make} {record.vehicle.model} · усі роботи одного відвідування', wide=True)
