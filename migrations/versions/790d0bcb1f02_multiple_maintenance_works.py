"""Allow multiple maintenance works in a single record, preserving existing text.

Revision ID: 790d0bcb1f02
Revises: 63fbfe322477
"""
from alembic import op
import sqlalchemy as sa

revision = '790d0bcb1f02'
down_revision = '63fbfe322477'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('maintenance_record', table_args=(sa.CheckConstraint('cost >= 0'), sa.CheckConstraint('mileage >= 0'))) as batch_op:
        batch_op.alter_column('work', existing_type=sa.String(length=120), type_=sa.Text(), existing_nullable=False)


def downgrade():
    connection = op.get_bind()
    if connection.scalar(sa.text('SELECT COUNT(*) FROM maintenance_record WHERE length(work) > 120')):
        raise RuntimeError('Cannot downgrade: some maintenance records exceed 120 characters. Export or shorten them first.')
    with op.batch_alter_table('maintenance_record', table_args=(sa.CheckConstraint('cost >= 0'), sa.CheckConstraint('mileage >= 0'))) as batch_op:
        batch_op.alter_column('work', existing_type=sa.Text(), type_=sa.String(length=120), existing_nullable=False)
