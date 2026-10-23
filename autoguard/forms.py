from datetime import date
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, DateField, DecimalField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange, Optional, Regexp, ValidationError
from wtforms.widgets import TextInput


class ManualDecimalField(DecimalField):
    def process_formdata(self, valuelist):
        values = [value.strip().replace(',', '.') for value in valuelist]
        if values and (len(values[0]) > 32 or not re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]{1,2})?', values[0])):
            self.data = None
            raise ValueError('Введіть звичайне число з не більш ніж двома знаками після коми.')
        super().process_formdata(values)


class WorkListField(StringField):
    """Repeated work inputs become one validated, newline-separated record."""
    def process_formdata(self, valuelist):
        self.data = '\n'.join(value.strip() for item in valuelist for value in item.splitlines() if value.strip())

    @property
    def items(self):
        return (self.data or '').splitlines() or ['']

    def pre_validate(self, form):
        if len(self.items) > 20:
            raise ValidationError('В одному записі можна додати до 20 робіт.')
        if any(len(item) > 120 for item in self.items):
            raise ValidationError('Назва кожної роботи має містити не більше 120 символів.')


def password_policy(form, field):
    p = field.data or ''
    if not (8 <= len(p) <= 128 and any(c.isupper() for c in p) and any(c.islower() for c in p)
            and any(c.isdigit() for c in p) and any(not c.isalnum() and not c.isspace() for c in p)):
        raise ValidationError('Пароль: 8–128 символів, велика й мала літери, цифра та спеціальний символ.')


class BaseForm(FlaskForm):
    class Meta:
        locales = ['uk']
    submit = SubmitField('Зберегти')


class EmailForm(BaseForm):
    email = StringField('Електронна пошта', validators=[DataRequired(), Email(), Length(max=254)])


class RegisterForm(EmailForm):
    name = StringField("Ім’я", validators=[DataRequired(), Length(min=2, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), password_policy])
    confirm = PasswordField('Повторіть пароль', validators=[DataRequired(), EqualTo('password', message='Паролі не збігаються.')])


class LoginForm(EmailForm):
    password = PasswordField('Пароль', validators=[DataRequired(), Length(max=128)])


class ResetForm(BaseForm):
    password = PasswordField('Новий пароль', validators=[DataRequired(), password_policy])
    confirm = PasswordField('Повторіть пароль', validators=[DataRequired(), EqualTo('password', message='Паролі не збігаються.')])


class CodeForm(BaseForm):
    code = StringField('Код автентифікатора', validators=[DataRequired(), Regexp(r'^[0-9]{6}$', message='Введіть 6 цифр від 0 до 9.')])


class DisableForm(CodeForm):
    password = PasswordField('Поточний пароль', validators=[Optional(), Length(max=128)])


class ProfileForm(BaseForm):
    name = StringField("Ім’я", validators=[DataRequired(), Length(min=2, max=80)])


class VehicleForm(BaseForm):
    make = StringField('Марка', validators=[DataRequired(), Length(max=50)],
                       render_kw={'data-autocomplete': 'make', 'placeholder': 'Почніть вводити, наприклад Toyota'})
    model = StringField('Модель', validators=[DataRequired(), Length(max=50)],
                        render_kw={'data-autocomplete': 'model', 'placeholder': 'Виберіть марку та почніть вводити модель'})
    year = IntegerField('Рік випуску', validators=[DataRequired(), NumberRange(min=1886, max=date.today().year+1)],
                        widget=TextInput(), render_kw={'inputmode': 'numeric', 'placeholder': '2021'})
    engine = SelectField('Тип двигуна', choices=['Бензин', 'Дизель', 'Гібрид', 'Електро', 'Газ'])
    mileage = IntegerField('Пробіг, км', validators=[NumberRange(min=0, max=10_000_000)],
                           widget=TextInput(), render_kw={'inputmode': 'numeric', 'placeholder': '45000'})
    vin = StringField('VIN (необов’язково)', validators=[Optional(), Regexp(r'^[A-HJ-NPR-Z0-9]{17}$', message='VIN: 17 великих латинських літер і цифр, без I, O, Q.')])


class MaintenanceForm(BaseForm):
    date = DateField('Дата', default=date.today, format=['%d.%m.%Y', '%Y-%m-%d'], validators=[DataRequired()],
                     widget=TextInput(), render_kw={'placeholder': 'ДД.ММ.РРРР', 'maxlength': '10'})
    work = WorkListField('Виконані роботи', validators=[DataRequired()],
                       render_kw={'data-autocomplete': 'work', 'placeholder': 'Виберіть підказку або введіть власну роботу'})
    mileage = IntegerField('Пробіг, км', validators=[NumberRange(min=0, max=10_000_000)],
                           widget=TextInput(), render_kw={'inputmode': 'numeric', 'placeholder': '45000'})
    cost = ManualDecimalField('Загальна вартість усіх робіт, грн', places=2, validators=[NumberRange(min=0, max=9999999999)],
                              widget=TextInput(), render_kw={'inputmode': 'decimal', 'placeholder': '1800,00'})
    notes = TextAreaField('Примітки', validators=[Optional(), Length(max=2000)])

    def validate_date(self, field):
        if field.data > date.today():
            raise ValidationError('Дата обслуговування не може бути в майбутньому.')
