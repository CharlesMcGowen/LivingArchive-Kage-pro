"""
Database router to route models to appropriate databases.
"""
class PostgresRouter:
    """Router for PostgreSQL models"""
    
    # Models for customer_eggs database
    customer_eggs_models = {
        'PostgresEggRecord',
        'PostgresNmap',
        'PostgresRequestMetadata',
        'PostgresDNSQuery',
    }
    
    # Models for eggrecords database
    eggrecords_models = {
        'KageWAFDetection',
        'KageTechniqueEffectiveness',
        'CalculatedHeuristicsRule',
        'WAFDetectionDetail',
        'IPTechniqueEffectiveness',
        'TechnologyFingerprint',
        'CVEFingerprintMatch',
        'NucleiTemplate',
        'KageScanResult',
        # Surge models
        'NucleiScan',
        'NucleiVulnerability',
        'SurgeKontrolDeployment',
    }
    
    def db_for_read(self, model, **hints):
        """Route read operations"""
        # Route Surge app models to eggrecords
        if model._meta.app_label == 'surge':
            return 'eggrecords'
        if model.__name__ in self.customer_eggs_models:
            return 'customer_eggs'
        elif model.__name__ in self.eggrecords_models:
            return 'eggrecords'
        return None
    
    def db_for_write(self, model, **hints):
        """Route write operations"""
        # Route Surge app models to eggrecords
        if model._meta.app_label == 'surge':
            return 'eggrecords'
        if model.__name__ in self.customer_eggs_models:
            return 'customer_eggs'
        elif model.__name__ in self.eggrecords_models:
            return 'eggrecords'
        return None
    
    def allow_relation(self, obj1, obj2, **hints):
        """Allow relations between models in the same database"""
        db_set = {'customer_eggs', 'eggrecords', 'default'}
        if obj1._state.db in db_set and obj2._state.db in db_set:
            return True
        return None
    
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """Control which migrations run on which database"""
        # Allow Surge app to migrate to eggrecords database
        if app_label == 'surge' and db == 'eggrecords':
            return True
        # Allow customer_eggs_eggrecords_general_models enrichment tables to migrate to eggrecords
        if app_label == 'customer_eggs_eggrecords_general_models' and db == 'eggrecords':
            # Only allow enrichment system models (TechnologyFingerprint, CVEFingerprintMatch)
            if model_name in ('TechnologyFingerprint', 'CVEFingerprintMatch'):
                return True
        # PostgreSQL models are managed=False, so no migrations
        if db in ('customer_eggs', 'eggrecords'):
            return False
        # Default database gets all migrations
        if db == 'default':
            return True
        return None

