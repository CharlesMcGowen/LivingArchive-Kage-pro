# Generated migration for CMSDefinition model

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('ryu_app', '0004_add_wordlist_upload_model'),
    ]

    operations = [
        migrations.CreateModel(
            name='CMSDefinition',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('cms_name', models.CharField(db_index=True, max_length=100, unique=True)),
                ('display_name', models.CharField(blank=True, max_length=200, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('filename_patterns', models.JSONField(default=list, help_text="List of filename patterns (e.g., ['wordpress', 'wp-'])")),
                ('path_patterns', models.JSONField(default=list, help_text="List of path patterns (e.g., ['/wp-admin/', '/wp-content/'])")),
                ('content_patterns', models.JSONField(default=list, help_text='List of content patterns for file content detection')),
                ('cms_type', models.CharField(choices=[('cms', 'CMS'), ('framework', 'Framework'), ('server', 'Server'), ('e-commerce', 'E-Commerce'), ('api-framework', 'API Framework'), ('enterprise', 'Enterprise')], default='cms', max_length=50)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.CharField(blank=True, max_length=100, null=True)),
            ],
            options={
                'verbose_name': 'CMS Definition',
                'verbose_name_plural': 'CMS Definitions',
                'ordering': ['cms_name'],
            },
        ),
        migrations.AddIndex(
            model_name='cmsdefinition',
            index=models.Index(fields=['cms_name', 'is_active'], name='ryu_app_cms_cms_nam_12345_idx'),
        ),
    ]

