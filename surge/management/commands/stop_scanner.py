#!/usr/bin/env python3
"""
Django management command to stop Surge autonomous scanner.
"""

from django.core.management.base import BaseCommand
import signal
import os
import psutil


class Command(BaseCommand):
    help = 'Stop Surge autonomous vulnerability scanner'

    def handle(self, *args, **options):
        self.stdout.write('🛑 Stopping Surge Autonomous Scanner...')
        
        # Find and stop scanner processes
        stopped = 0
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and any('start_scanner' in arg or 'autonomous_scanner' in arg for arg in cmdline):
                    self.stdout.write(f'   Stopping process {proc.info["pid"]}...')
                    proc.terminate()
                    stopped += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        if stopped > 0:
            self.stdout.write(self.style.SUCCESS(f'✅ Stopped {stopped} scanner process(es)'))
        else:
            self.stdout.write(self.style.WARNING('⚠️  No running scanner processes found'))
        
        return 0

