from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Length, ValidationError
from flask_wtf.file import FileField, FileRequired, FileAllowed 
import bleach

class FileSizeValidator:
    def __init__(self, max_size_mb, message=None):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.message = message or f'File must be less than {max_size_mb} MB.'

    def __call__(self, form, field):
        if field.data: 
            if field.data.content_length > self.max_size_bytes:
                raise ValidationError(self.message)


class SubmissionForm(FlaskForm):
    submission_type = SelectField(
        'Submission Type',
        choices=[('', 'Select how you\'re submitting'), ('photos', 'Photos of Project & Session'), ('video', 'Short Video Journal'), ('document', 'Reflection Essay / Document')],
        validators=[DataRequired(message="Please select a submission type.")],
        render_kw={"class": "form-select rounded"}
    )
    
    uploaded_file = FileField(
        'Upload Your Files',
        validators=[
            FileRequired(message="Please upload at least one file."),
            FileAllowed(['jpg', 'png', 'mp4', 'pdf', 'doc', 'docx'], 'Images (JPG, PNG), Video (MP4), Documents (PDF, DOCX) only!'),
            FileSizeValidator(max_size_mb=50, message='File size exceeds 50MB limit.') 
        ]
    )
    project_title = StringField(
        'Project Title',
        validators=[DataRequired(message="Project title is required."), Length(min=3, max=100, message="Title must be between 3 and 100 characters.")],
        filters=[lambda text: bleach.clean(text, tags=[], strip=True) if text else text],    
        render_kw={"class": "form-control rounded", "placeholder": "Give your project a name"}
    )
    reflection_story = TextAreaField(
        'Your Reflection & Story',
        validators=[DataRequired(message="Reflection story is required."), Length(min=50, max=300, message="Reflection must be between 50 and 300 characters.")],
        filters=[lambda text: bleach.clean(text, tags=[], strip=True) if text else text],    
        render_kw={"class": "form-control rounded", "rows": "8", "placeholder": "Tell us about your experience! What did you learn? What was your favorite part of connecting with your elder mentor? Describe the project you created."}
    )
    confirmation_check = BooleanField(
        'I confirm that my submission is authentic, complete, and reflects my experience with the challenge.',
        validators=[DataRequired(message="You must confirm your submission.")]
    )
    g_recaptcha_response = HiddenField()
    submit = SubmitField('Submit Challenge')


class AcceptChallengeForm(FlaskForm):
    submit = SubmitField('Accept Challenge')

class CommentForm(FlaskForm):
    comment = TextAreaField(
        'Comment', 
        validators=[
            DataRequired(message="Comment cannot be empty."),
            Length(min=1, max=1000, message="Comment must be between 1 and 1000 characters.")
        ],
        filters=[lambda text: bleach.clean(text, tags=[], strip=True) if text else text]
    )
    g_recaptcha_response = HiddenField() 
    submit = SubmitField('Submit for Review')