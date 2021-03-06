"""database init

Revision ID: d553005bdda0
Revises: 
Create Date: 2020-12-22 17:36:30.809480

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd553005bdda0'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('login_attempts', sa.Integer(), server_default='0', nullable=True),
    sa.Column('login_success', sa.Integer(), server_default='0', nullable=True),
    sa.Column('employee_identification', sa.String(length=128), nullable=True),
    sa.Column('role', sa.Integer(), server_default='0', nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('employee_identification')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_email'), table_name='user')
    op.drop_table('user')
    # ### end Alembic commands ###
