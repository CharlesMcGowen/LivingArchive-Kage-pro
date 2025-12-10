"""create_ash_learning_tables

Revision ID: 685ea58e272e
Revises: 
Create Date: 2025-12-01 01:58:21.232233

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '685ea58e272e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create ash_technique_effectiveness table
    op.create_table(
        'ash_technique_effectiveness',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column('target_pattern', sa.String(255), nullable=False),
        sa.Column('waf_type', sa.String(50), nullable=True),
        sa.Column('technique_name', sa.String(100), nullable=False),
        sa.Column('success_count', sa.Integer(), default=0, nullable=False),
        sa.Column('failure_count', sa.Integer(), default=0, nullable=False),
        sa.Column('last_success', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_failure', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_updated', sa.DateTime(timezone=True), default=sa.func.now(), nullable=False),
        sa.Column('technique_metadata', postgresql.JSONB(), default={}, nullable=True),
        sa.Index('idx_technique_target_waf', 'target_pattern', 'waf_type', 'technique_name', unique=True),
        sa.Index('idx_technique_success_rate', 'target_pattern', 'waf_type'),
    )
    
    # Create ash_waf_detections table
    op.create_table(
        'ash_waf_detections',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('waf_type', sa.String(50), nullable=True),
        sa.Column('detection_method', sa.String(50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, default=0.0),
        sa.Column('signatures', postgresql.JSONB(), default={}, nullable=True),
        sa.Column('response_headers', postgresql.JSONB(), default={}, nullable=True),
        sa.Column('response_body_sample', sa.Text(), nullable=True),
        sa.Column('bypass_technique', sa.String(100), nullable=True),
        sa.Column('bypass_successful', sa.Boolean(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), default=sa.func.now(), nullable=False),
        sa.Index('idx_waf_target_time', 'target', 'detected_at'),
        sa.Index('idx_waf_type', 'waf_type'),
    )
    
    # Create ash_scan_results table
    op.create_table(
        'ash_scan_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('egg_record_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('technique_used', sa.String(100), nullable=False),
        sa.Column('ports_scanned', postgresql.JSONB(), default=[], nullable=True),
        sa.Column('open_ports_found', sa.Integer(), default=0, nullable=False),
        sa.Column('waf_detected', sa.Boolean(), default=False, nullable=False),
        sa.Column('waf_type', sa.String(50), nullable=True),
        sa.Column('bypass_successful', sa.Boolean(), nullable=True),
        sa.Column('scan_duration', sa.Float(), nullable=True),
        sa.Column('scan_results', postgresql.JSONB(), default={}, nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), default=sa.func.now(), nullable=False),
        sa.Index('idx_scan_target_time', 'target', 'scanned_at'),
        sa.Index('idx_scan_technique', 'technique_used'),
        sa.Index('idx_scan_waf', 'waf_detected', 'waf_type'),
    )


def downgrade() -> None:
    op.drop_table('ash_scan_results')
    op.drop_table('ash_waf_detections')
    op.drop_table('ash_technique_effectiveness')

