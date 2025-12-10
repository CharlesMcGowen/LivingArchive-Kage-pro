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
        'AshWAFDetection',
        'AshTechniqueEffectiveness',
        'CalculatedHeuristicsRule',
        'WAFDetectionDetail',
        'IPTechniqueEffectiveness',
        'TechnologyFingerprint',
        'AshScanResult',
    }
    
    def db_for_read(self, model, **hints):
        """Route read operations"""
        if model.__name__ in self.customer_eggs_models:
            return 'customer_eggs'
        elif model.__name__ in self.eggrecords_models:
            return 'eggrecords'
        return None
    
    def db_for_write(self, model, **hints):
        """Route write operations"""
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
        # PostgreSQL models are managed=False, so no migrations
        if db in ('customer_eggs', 'eggrecords'):
            return False
        # Default database gets all migrations
        if db == 'default':
            return True
        return None

