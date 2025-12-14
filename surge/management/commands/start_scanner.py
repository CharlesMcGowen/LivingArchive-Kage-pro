#!/usr/bin/env python3
"""
Django management command to start Surge autonomous scanner.
"""

from django.core.management.base import BaseCommand
import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from surge.agents.autonomous_scanner import SurgeAutonomousScanner


class Command(BaseCommand):
    help = 'Start Surge autonomous vulnerability scanner'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=300,
            help='Scan interval in seconds (default: 300)',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=5,
            help='Number of targets per batch (default: 5)',
        )
        parser.add_argument(
            '--scan-type',
            type=str,
            default='quick',
            choices=['quick', 'comprehensive', 'stealth', 'aggressive'],
            help='Type of scan to perform (default: quick)',
        )
        parser.add_argument(
            '--continuous',
            action='store_true',
            default=True,
            help='Run continuously (default: True)',
        )
        parser.add_argument(
            '--single-run',
            action='store_true',
            help='Run once and exit (overrides --continuous)',
        )

    def handle(self, *args, **options):
        # Set environment variables from options
        if options['interval']:
            os.environ['SURGE_SCAN_INTERVAL'] = str(options['interval'])
        if options['batch_size']:
            os.environ['SURGE_BATCH_SIZE'] = str(options['batch_size'])
        if options['scan_type']:
            os.environ['SURGE_SCAN_TYPE'] = options['scan_type']
        if options['single_run']:
            os.environ['SURGE_CONTINUOUS'] = 'false'
        elif options['continuous']:
            os.environ['SURGE_CONTINUOUS'] = 'true'

        self.stdout.write(self.style.SUCCESS('⚡ Starting Surge Autonomous Scanner...'))
        
        # Create and run scanner
        scanner = SurgeAutonomousScanner()
        
        try:
            asyncio.run(scanner.run())
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\n⚠️  Scanner stopped by user'))
            scanner.stop()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Error: {e}'))
            return 1
        
        return 0

