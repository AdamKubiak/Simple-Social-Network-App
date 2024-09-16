"""add password

Revision ID: 738e784366d4
Revises: 6fb7f703560f
Create Date: 2024-09-10 11:11:06.380151

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '738e784366d4'
down_revision = '6fb7f703560f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_hash', sa.String(length=256), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('password_hash')

    # ### end Alembic commands ###
