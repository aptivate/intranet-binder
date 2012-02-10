from haystack import indexes, fields

from models import IntranetUser

class UserIndex(indexes.RealTimeSearchIndex, indexes.Indexable):
    text = fields.CharField(model_attr='full_name', document=True)
    title = fields.CharField(model_attr='full_name')
    job_title = fields.CharField(model_attr='job_title')
    programs = fields.MultiValueField()
    program = fields.CharField(model_attr='program', null=True)
    
    def get_model(self):
        return IntranetUser
    
    def prepare_programs(self, user):
        if user.program is None:
            return []
        else:
            return [user.program.id]
