from datetime import date
from decimal import Decimal
import re
from pathlib import Path
from flask_migrate import upgrade
from sqlalchemy import inspect
from werkzeug.datastructures import MultiDict
from autoguard.extensions import db
from autoguard.models import User, Vehicle, MaintenanceRecord


def add_vehicle(app, client, make_user, login):
    make_user()
    login()
    client.post('/garage/new', data={'make':'Toyota','model':'Corolla','year':'2021','engine':'Гібрид','mileage':'45000','vin':''})
    with app.app_context():
        return db.session.scalar(db.select(Vehicle)).id


def service_data(works):
    return MultiDict([('work',work) for work in works] + [
        ('date',date.today().strftime('%d.%m.%Y')),('mileage','46000'),('cost','1800,50'),('notes','Одне відвідування СТО')])


def test_multiple_works_one_record_one_total(app,client,make_user,login):
    vid=add_vehicle(app,client,make_user,login)
    works=['Заміна моторної оливи','Моя власна робота','Заміна гальмівних колодок']
    assert client.post(f'/garage/{vid}',data=service_data(works)).status_code==302
    with app.app_context():
        records=db.session.scalars(db.select(MaintenanceRecord)).all()
        assert len(records)==1
        assert records[0].work_items==works
        assert records[0].date==date.today()
        assert records[0].cost==Decimal('1800.50')
        assert db.session.get(Vehicle,vid).mileage==46000
    for path in [f'/garage/{vid}','/history','/dashboard']:
        html=client.get(path).get_data(as_text=True)
        assert all(work in html for work in works)
    assert b'1800.50' in client.get('/statistics').data


def test_invalid_multiple_works_keep_user_input(app,client,make_user,login):
    vid=add_vehicle(app,client,make_user,login)
    for works in [[],['   '],['x'*121],['Work']*21]:
        assert client.post(f'/garage/{vid}',data=service_data(works)).status_code==200
    data=service_data(['Перша робота','Друга робота'])
    data['cost']='invalid'
    html=client.post(f'/garage/{vid}',data=data).get_data(as_text=True)
    assert 'value="Перша робота"' in html and 'value="Друга робота"' in html
    with app.app_context():
        assert db.session.scalar(db.select(MaintenanceRecord)) is None


def test_blank_extra_work_is_optional_and_escaped(app,client,make_user,login):
    vid=add_vehicle(app,client,make_user,login)
    assert client.post(f'/garage/{vid}',data=service_data(['  Перевірка  ','','<img src=x onerror=alert(1)>'])).status_code==302
    html=client.get('/history').get_data(as_text=True)
    assert '&lt;img' in html and '<img src=x' not in html
    with app.app_context():
        assert db.session.scalar(db.select(MaintenanceRecord)).work_items==['Перевірка','<img src=x onerror=alert(1)>']


def test_manual_inputs_have_no_number_or_date_controls(app,client,make_user,login):
    vid=add_vehicle(app,client,make_user,login)
    for path,names in [('/garage/new',['year','mileage']),(f'/garage/{vid}',['date','mileage','cost'])]:
        html=client.get(path).get_data(as_text=True)
        for name in names:
            tag=re.search(r'<input\b[^>]*\bname="'+name+r'"[^>]*>',html).group()
            assert 'type="text"' in tag
        assert 'type="number"' not in html and 'type="date"' not in html


def test_migration_preserves_old_records_and_constraints(app):
    migrations=str(Path(__file__).resolve().parents[1]/'migrations')
    with app.app_context():
        db.drop_all()
        upgrade(directory=migrations,revision='63fbfe322477')
        user=User(email='migration@example.com',name='Migration',activated=True)
        db.session.add(user)
        db.session.flush()
        vehicle=Vehicle(user_id=user.id,make='Toyota',model='Corolla',year=2021,engine='Гібрид',mileage=100)
        db.session.add(vehicle)
        db.session.flush()
        record=MaintenanceRecord(vehicle_id=vehicle.id,date=date.today(),work='Старий запис',mileage=100,cost=Decimal('123.45'),notes='Збережена примітка')
        db.session.add(record)
        db.session.commit()
        rid,vid=record.id,vehicle.id
        db.session.remove()
        upgrade(directory=migrations)
        old=db.session.get(MaintenanceRecord,rid)
        assert old.work_items==['Старий запис'] and old.cost==Decimal('123.45')
        assert old.vehicle_id==vid and old.notes=='Збережена примітка'
        constraints={item['sqltext'] for item in inspect(db.engine).get_check_constraints('maintenance_record')}
        assert {'cost >= 0','mileage >= 0'} <= constraints
        assert inspect(db.engine).get_foreign_keys('maintenance_record')[0]['referred_table']=='vehicle'
        old.work='\n'.join(['Довга назва роботи '*5]*3)
        db.session.commit()
        assert len(db.session.get(MaintenanceRecord,rid).work_items)==3
