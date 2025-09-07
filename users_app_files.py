# users models.py:
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager
from django.db import models
from django.utils.text import slugify
from django.utils import timezone
from django.core.validators import RegexValidator
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import timedelta


class CustomUserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with an email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_organizer', True)
        extra_fields.setdefault('is_email_verified', True)
        extra_fields.setdefault('account_status', 'active')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class Permission(models.Model):
    """Permission model for granular access control."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    codename = models.CharField(max_length=100, unique=True, help_text="Unique permission identifier")
    name = models.CharField(max_length=200, help_text="Human-readable permission name")
    description = models.TextField(blank=True, help_text="Detailed description of what this permission allows")
    category = models.CharField(max_length=50, default='general', help_text="Permission category for organization")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_permissions'
        verbose_name = 'Permission'
        verbose_name_plural = 'Permissions'
        ordering = ['category', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.codename})"


class Role(models.Model):
    """Role model for RBAC system with hierarchical support."""
    ROLE_TYPES = [
        ('admin', 'Administrator'),
        ('organizer', 'Organizer'),
        ('team_member', 'Team Member'),
        ('billing_manager', 'Billing Manager'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, unique=True)
    role_type = models.CharField(max_length=20, choices=ROLE_TYPES)
    description = models.TextField(blank=True)
    
    # Hierarchical role support
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, 
                              related_name='children', help_text="Parent role for inheritance")
    
    # Permission relationships
    role_permissions = models.ManyToManyField(Permission, blank=True, related_name='roles',
                                            help_text="Permissions directly assigned to this role")
    
    # Hierarchy and organization
    is_system_role = models.BooleanField(default=False, help_text="System roles cannot be deleted")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_roles'
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def get_all_permissions(self):
        """Get all permissions for this role, including inherited from parent roles."""
        permissions = set(self.role_permissions.all())
        
        # Recursively collect permissions from parent roles
        current_role = self.parent
        while current_role:
            permissions.update(current_role.role_permissions.all())
            current_role = current_role.parent
        
        return list(permissions)
    
    def has_permission(self, permission_codename):
        """Check if this role has a specific permission (including inherited)."""
        all_permissions = self.get_all_permissions()
        return any(perm.codename == permission_codename for perm in all_permissions)
    
    def get_permission_codenames(self):
        """Get list of permission codenames for this role."""
        return [perm.codename for perm in self.get_all_permissions()]


class User(AbstractUser):
    """Extended User model with additional fields for organizers."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Remove username field from AbstractUser
    username = None  

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)

    USERNAME_FIELD = "email"  # Email is the unique identifier
    REQUIRED_FIELDS = ["first_name", "last_name"]  # Prompted when creating superuser
    
    # Assign the custom manager
    objects = CustomUserManager()
    
    # Enhanced user status fields
    is_organizer = models.BooleanField(default=True)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    is_mfa_enabled = models.BooleanField(default=False)
    
    # Account management
    account_status = models.CharField(
        max_length=50,
        choices=[
            ('active', 'Active'),
            ('inactive', 'Inactive'),
            ('suspended', 'Suspended'),
            ('pending_verification', 'Pending Verification'),
            ('password_expired', 'Password Expired'),
            ('password_expired_grace_period', 'Password Expired (Grace Period)'),
        ],
        default='pending_verification'
    )
    
    # Password management
    password_changed_at = models.DateTimeField(null=True, blank=True)
    password_expires_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # RBAC
    roles = models.ManyToManyField(Role, blank=True, related_name='users')
    
    # MFA Settings
    mfa_secret = models.CharField(max_length=32, blank=True, help_text="TOTP secret key")
    mfa_backup_codes = models.JSONField(default=list, blank=True, help_text="List of backup codes")
    mfa_last_used_code = models.CharField(max_length=10, blank=True, help_text="Last used backup code")
    
    # Audit fields
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    def has_role(self, role_name):
        """Check if user has a specific role."""
        return self.roles.filter(name=role_name).exists()
    
    def has_permission(self, permission):
        """Check if user has a specific permission through their roles (including inherited)."""
        for role in self.roles.all():
            if role.has_permission(permission):
                return True
        return False
    
    def get_all_permissions(self):
        """Get all permissions for this user from all their roles."""
        all_permissions = set()
        for role in self.roles.all():
            all_permissions.update(role.get_all_permissions())
        return list(all_permissions)
    
    def is_account_locked(self):
        """Check if account is locked due to failed login attempts."""
        return self.locked_until and self.locked_until > timezone.now()
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration."""
        self.locked_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.save(update_fields=['locked_until'])
    
    def unlock_account(self):
        """Unlock account and reset failed login attempts."""
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['locked_until', 'failed_login_attempts'])
    
    def generate_mfa_secret(self):
        """Generate a new MFA secret key."""
        self.mfa_secret = pyotp.random_base32()
        self.save(update_fields=['mfa_secret'])
        return self.mfa_secret
    
    def get_totp_uri(self):
        """Get TOTP URI for QR code generation."""
        if not self.mfa_secret:
            self.generate_mfa_secret()
        
        return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.email,
            issuer_name="Calendly Clone"
        )
    
    def verify_totp(self, token):
        """Verify TOTP token."""
        if not self.mfa_secret:
            return False
        
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self, count=10):
        """Generate backup codes for MFA recovery."""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            codes.append(code)
        
        self.mfa_backup_codes = codes
        self.save(update_fields=['mfa_backup_codes'])
        return codes
    
    def verify_backup_code(self, code):
        """Verify and consume a backup code."""
        if not self.mfa_backup_codes or code.upper() not in self.mfa_backup_codes:
            return False
        
        # Remove used code
        self.mfa_backup_codes.remove(code.upper())
        self.mfa_last_used_code = code.upper()
        self.save(update_fields=['mfa_backup_codes', 'mfa_last_used_code'])
        return True
    
    def disable_mfa(self):
        """Disable MFA for user."""
        self.is_mfa_enabled = False
        self.mfa_secret = ''
        self.mfa_backup_codes = []
        self.mfa_last_used_code = ''
        self.save(update_fields=['is_mfa_enabled', 'mfa_secret', 'mfa_backup_codes', 'mfa_last_used_code'])


class Profile(models.Model):
    """Profile model for organizer-specific settings."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    organizer_slug = models.SlugField(max_length=100, unique=True, blank=True)
    display_name = models.CharField(max_length=100, blank=True)
    bio = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    
    # Contact information
    phone_validator = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone = models.CharField(validators=[phone_validator], max_length=17, blank=True)
    website = models.URLField(blank=True)
    company = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    
    # Localization
    timezone_name = models.CharField(max_length=50, default='UTC')
    language = models.CharField(max_length=10, default='en')
    date_format = models.CharField(max_length=20, default='MM/DD/YYYY')
    time_format = models.CharField(max_length=10, default='12h')
    
    # Branding settings
    brand_color = models.CharField(max_length=7, default='#0066cc')  # Hex color
    brand_logo = models.ImageField(upload_to='brand_logos/', blank=True, null=True)
    
    # Privacy settings
    public_profile = models.BooleanField(default=True)
    show_phone = models.BooleanField(default=False)
    show_email = models.BooleanField(default=True)
    
    # Multi-invitee scheduling settings
    reasonable_hours_start = models.IntegerField(
        default=7, 
        validators=[MinValueValidator(0), MaxValueValidator(23)],
        help_text="Start of reasonable hours for multi-invitee scheduling (24-hour format)"
    )
    reasonable_hours_end = models.IntegerField(
        default=22, 
        validators=[MinValueValidator(1), MaxValueValidator(24)],
        help_text="End of reasonable hours for multi-invitee scheduling (24-hour format)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'Profile'
        verbose_name_plural = 'Profiles'
    
    def __str__(self):
        return f"Profile for {self.user.email}"
    
    def save(self, *args, **kwargs):
        if not self.organizer_slug:
            base_slug = slugify(f"{self.user.first_name}-{self.user.last_name}")
            
            # Check if base slug is unique
            if Profile.objects.filter(organizer_slug=base_slug).exists():
                # Append UUID fragment for uniqueness
                uuid_fragment = uuid.uuid4().hex[:6]
                slug = f"{base_slug}-{uuid_fragment}"
            else:
                slug = base_slug
            
            self.organizer_slug = slug
        
        if not self.display_name:
            self.display_name = f"{self.user.first_name} {self.user.last_name}"
        
        super().save(*args, **kwargs)


class EmailVerificationToken(models.Model):
    """Token model for email verification."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_verification_tokens')
    email = models.EmailField()  # The email being verified (might be different from current user email)
    token = models.CharField(max_length=64, unique=True)
    token_type = models.CharField(
        max_length=20,
        choices=[
            ('email_verification', 'Email Verification'),
            ('email_change', 'Email Change'),
        ],
        default='email_verification'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'email_verification_tokens'
        verbose_name = 'Email Verification Token'
        verbose_name_plural = 'Email Verification Tokens'
    
    def __str__(self):
        return f"Email verification for {self.email}"
    
    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if token is still valid."""
        return not self.used_at and self.expires_at > timezone.now()
    
    def mark_as_used(self):
        """Mark token as used."""
        self.used_at = timezone.now()
        self.save(update_fields=['used_at'])


class PasswordResetToken(models.Model):
    """Token model for password reset."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=64, unique=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    
    # Security tracking
    created_ip = models.GenericIPAddressField(null=True, blank=True)
    used_ip = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'password_reset_tokens'
        verbose_name = 'Password Reset Token'
        verbose_name_plural = 'Password Reset Tokens'
    
    def __str__(self):
        return f"Password reset for {self.user.email}"
    
    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=1)  # Shorter expiry for security
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if token is still valid."""
        return not self.used_at and self.expires_at > timezone.now()
    
    def mark_as_used(self, ip_address=None):
        """Mark token as used."""
        self.used_at = timezone.now()
        if ip_address:
            self.used_ip = ip_address
        self.save(update_fields=['used_at', 'used_ip'])


class PasswordHistory(models.Model):
    """Store password history to prevent reuse."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'password_history'
        verbose_name = 'Password History'
        verbose_name_plural = 'Password History'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Password history for {self.user.email} - {self.created_at}"


class Invitation(models.Model):
    """Model for team member invitations."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    invited_email = models.EmailField()
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, unique=True)
    
    # Optional personal message
    message = models.TextField(blank=True)
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('accepted', 'Accepted'),
            ('declined', 'Declined'),
            ('expired', 'Expired'),
        ],
        default='pending'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    responded_at = models.DateTimeField(null=True, blank=True)
    
    # User who accepted (if different from email)
    accepted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='accepted_invitations')
    
    class Meta:
        db_table = 'user_invitations'
        verbose_name = 'Invitation'
        verbose_name_plural = 'Invitations'
        unique_together = ['invited_by', 'invited_email', 'status']  # Prevent duplicate pending invitations
    
    def __str__(self):
        return f"Invitation to {self.invited_email} from {self.invited_by.email}"
    
    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=7)  # 7 days to accept
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if invitation is still valid."""
        return self.status == 'pending' and self.expires_at > timezone.now()
    
    def accept(self, user):
        """Mark invitation as accepted."""
        self.status = 'accepted'
        self.responded_at = timezone.now()
        self.accepted_by = user
        self.save(update_fields=['status', 'responded_at', 'accepted_by'])
        
        # Add role to user
        user.roles.add(self.role)
    
    def decline(self):
        """Mark invitation as declined."""
        self.status = 'declined'
        self.responded_at = timezone.now()
        self.save(update_fields=['status', 'responded_at'])


class AuditLog(models.Model):
    """Audit log for tracking user actions."""
    ACTION_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('login_failed', 'Login Failed'),
        ('password_changed', 'Password Changed'),
        ('password_reset_requested', 'Password Reset Requested'),
        ('password_reset_completed', 'Password Reset Completed'),
        ('password_expiry_warning_sent', 'Password Expiry Warning Sent'),
        ('forced_password_change', 'Forced Password Change'),
        ('password_grace_period_expired', 'Password Grace Period Expired'),
        ('email_verified', 'Email Verified'),
        ('profile_updated', 'Profile Updated'),
        ('role_assigned', 'Role Assigned'),
        ('role_removed', 'Role Removed'),
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
        ('mfa_enabled', 'MFA Enabled'),
        ('mfa_disabled', 'MFA Disabled'),
        ('invitation_sent', 'Invitation Sent'),
        ('invitation_accepted', 'Invitation Accepted'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs', null=True, blank=True)
    action = models.CharField(max_length=30, choices=ACTION_TYPES)
    description = models.TextField()
    
    # Context information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    session_key = models.CharField(max_length=40, blank=True)
    
    # Additional data
    metadata = models.JSONField(default=dict, blank=True, help_text="Additional context data")
    
    # Generic foreign key for linking to related objects
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.UUIDField(null=True, blank=True)
    related_object = GenericForeignKey('content_type', 'object_id')
    
    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'user_audit_logs'
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['action', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
        ]
    
    def __str__(self):
        user_info = f"{self.user.email}" if self.user else "Anonymous"
        related_info = f" on {self.related_object}" if self.related_object else ""
        return f"{user_info} - {self.get_action_display()}{related_info} - {self.created_at}"


class UserSession(models.Model):
    """Track active user sessions."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='active_sessions')
    session_key = models.CharField(max_length=40, unique=True)
    
    # Session information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    country = models.CharField(max_length=100, blank=True, help_text="Country from IP geolocation")
    city = models.CharField(max_length=100, blank=True, help_text="City from IP geolocation")
    device_info = models.JSONField(default=dict, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    
    # Status
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'user_sessions'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-last_activity']
    
    def __str__(self):
        return f"{self.user.email} - {self.ip_address} - {self.created_at}"
    
    def is_expired(self):
        """Check if session is expired."""
        return timezone.now() > self.expires_at
    
    def revoke(self):
        """Revoke the session."""
        self.is_active = False
        self.save(update_fields=['is_active'])


class MFADevice(models.Model):
    """MFA device model for tracking user's MFA devices."""
    DEVICE_TYPES = [
        ('totp', 'TOTP Authenticator'),
        ('sms', 'SMS'),
        ('backup', 'Backup Codes'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_devices')
    device_type = models.CharField(max_length=10, choices=DEVICE_TYPES)
    name = models.CharField(max_length=100, help_text="User-friendly device name")
    
    # Device-specific data
    phone_number = models.CharField(max_length=20, blank=True, help_text="For SMS devices")
    verification_attempts = models.IntegerField(default=0, help_text="Number of verification attempts")
    last_verification_attempt = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_primary = models.BooleanField(default=False, help_text="Primary MFA device")
    
    # Usage tracking
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'mfa_devices'
        verbose_name = 'MFA Device'
        verbose_name_plural = 'MFA Devices'
        unique_together = ['user', 'device_type', 'is_primary']
    
    def __str__(self):
        return f"{self.user.email} - {self.get_device_type_display()} - {self.name}"
    
    def can_attempt_verification(self):
        """Check if device can attempt verification (rate limiting)."""
        from django.utils import timezone
        from datetime import timedelta
        
        # Allow 5 attempts per hour
        if self.verification_attempts >= 5:
            if self.last_verification_attempt:
                time_since_last = timezone.now() - self.last_verification_attempt
                if time_since_last < timedelta(hours=1):
                    return False
            # Reset attempts after an hour
            self.verification_attempts = 0
            self.save(update_fields=['verification_attempts'])
        
        return True
    
    def record_verification_attempt(self):
        """Record a verification attempt."""
        from django.utils import timezone
        self.verification_attempts += 1
        self.last_verification_attempt = timezone.now()
        self.save(update_fields=['verification_attempts', 'last_verification_attempt'])


class SAMLConfiguration(models.Model):
    """SAML SSO configuration for enterprise clients."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Organization details
    organization_name = models.CharField(max_length=200)
    organization_domain = models.CharField(max_length=100, unique=True)
    
    # SAML settings
    entity_id = models.URLField(help_text="Identity Provider Entity ID")
    sso_url = models.URLField(help_text="Single Sign-On URL")
    slo_url = models.URLField(blank=True, help_text="Single Logout URL")
    x509_cert = models.TextField(help_text="X.509 Certificate")
    
    # Attribute mapping
    email_attribute = models.CharField(max_length=100, default='email')
    first_name_attribute = models.CharField(max_length=100, default='first_name')
    last_name_attribute = models.CharField(max_length=100, default='last_name')
    role_attribute = models.CharField(max_length=100, blank=True, help_text="Attribute for role mapping")
    
    # Settings
    is_active = models.BooleanField(default=True)
    auto_provision_users = models.BooleanField(default=True, help_text="Create users automatically via JIT")
    default_role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'saml_configurations'
        verbose_name = 'SAML Configuration'
        verbose_name_plural = 'SAML Configurations'
    
    def __str__(self):
        return f"SAML Config - {self.organization_name}"


class OIDCConfiguration(models.Model):
    """OpenID Connect configuration for enterprise SSO."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Organization details
    organization_name = models.CharField(max_length=200)
    organization_domain = models.CharField(max_length=100, unique=True)
    
    # OIDC settings
    issuer = models.URLField(help_text="OIDC Issuer URL")
    client_id = models.CharField(max_length=200)
    client_secret = models.CharField(max_length=500)
    
    # Endpoints (auto-discovered or manual)
    authorization_endpoint = models.URLField(blank=True)
    token_endpoint = models.URLField(blank=True)
    userinfo_endpoint = models.URLField(blank=True)
    jwks_uri = models.URLField(blank=True)
    
    # Scopes and claims
    scopes = models.JSONField(default=list, help_text="List of requested scopes")
    email_claim = models.CharField(max_length=100, default='email')
    first_name_claim = models.CharField(max_length=100, default='given_name')
    last_name_claim = models.CharField(max_length=100, default='family_name')
    role_claim = models.CharField(max_length=100, blank=True)
    
    # Settings
    is_active = models.BooleanField(default=True)
    auto_provision_users = models.BooleanField(default=True)
    default_role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'oidc_configurations'
        verbose_name = 'OIDC Configuration'
        verbose_name_plural = 'OIDC Configurations'
    
    def __str__(self):
        return f"OIDC Config - {self.organization_name}"


class SSOSession(models.Model):
    """Track SSO sessions for federation and logout."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sso_sessions')
    
    # SSO details
    sso_type = models.CharField(max_length=20, choices=[
        ('saml', 'SAML'),
        ('oidc', 'OpenID Connect'),
        ('oauth', 'OAuth'),
    ])
    provider_name = models.CharField(max_length=100)
    external_session_id = models.CharField(max_length=200, blank=True)
    
    # Session data
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    
    # Status
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'sso_sessions'
        verbose_name = 'SSO Session'
        verbose_name_plural = 'SSO Sessions'
        ordering = ['-last_activity']
    
    def __str__(self):
        return f"{self.user.email} - {self.sso_type.upper()} - {self.provider_name}"

# users serializers.py:
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import (
    User, Profile, Role, Permission, EmailVerificationToken, PasswordResetToken,
    Invitation, AuditLog, UserSession, MFADevice, SAMLConfiguration, OIDCConfiguration
)


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'description', 'category']
        read_only_fields = ['id']
class RoleSerializer(serializers.ModelSerializer):
    role_permissions = PermissionSerializer(many=True, read_only=True)
    parent_name = serializers.CharField(source='parent.name', read_only=True)
    children_count = serializers.IntegerField(source='children.count', read_only=True)
    total_permissions = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = ['id', 'name', 'role_type', 'description', 'parent', 'parent_name', 
                 'children_count', 'role_permissions', 'total_permissions', 'is_system_role']
        read_only_fields = ['id']
    
    def get_total_permissions(self, obj):
        return len(obj.get_all_permissions())


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'organizer_slug', 'display_name', 'bio', 'profile_picture',
            'phone', 'website', 'company', 'job_title', 'timezone_name',
            'language', 'date_format', 'time_format', 'brand_color',
            'brand_logo', 'public_profile', 'show_phone', 'show_email',
            'reasonable_hours_start', 'reasonable_hours_end'
        ]
        read_only_fields = ['organizer_slug']


class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    roles = RoleSerializer(many=True, read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'is_organizer', 'is_email_verified', 'is_phone_verified',
            'is_mfa_enabled', 'account_status', 'roles', 'profile',
            'last_login', 'date_joined'
        ]
        read_only_fields = [
            'id', 'is_email_verified', 'is_phone_verified', 'is_mfa_enabled',
            'last_login', 'date_joined'
        ]
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    terms_accepted = serializers.BooleanField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'last_name',
            'password', 'password_confirm', 'terms_accepted'
        ]
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        if not attrs.get('terms_accepted'):
            raise serializers.ValidationError("You must accept the terms and conditions")
        
        # Validate password strength
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({'password': e.messages})
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        validated_data.pop('terms_accepted')
        
        # Set username to email since our User model uses email as USERNAME_FIELD
        validated_data['username'] = validated_data['email']
        
        user = User.objects.create_user(**validated_data)
        user.password_changed_at = timezone.now()
        user.save(update_fields=['password_changed_at'])
        
        # Assign default role
        default_role, created = Role.objects.get_or_create(
            name='organizer',
            defaults={
                'role_type': 'organizer',
                'is_system_role': True
            }
        )
        
        # Add permissions to the role if it was just created
        if created:
            # Get or create the required permissions
            create_events_perm, _ = Permission.objects.get_or_create(
                codename='can_create_events',
                defaults={
                    'name': 'Create Events',
                    'description': 'Can create event types',
                    'category': 'event_management'
                }
            )
            manage_bookings_perm, _ = Permission.objects.get_or_create(
                codename='can_manage_bookings',
                defaults={
                    'name': 'Manage Bookings',
                    'description': 'Can manage all bookings',
                    'category': 'event_management'
                }
            )
            
            # Add permissions to the role
            default_role.role_permissions.add(create_events_perm, manage_bookings_perm)
        
        
        # Add permissions to the role if it was just created
        if created:
            # Get or create the required permissions
            create_events_perm, _ = Permission.objects.get_or_create(
                codename='can_create_events',
                defaults={
                    'name': 'Create Events',
                    'description': 'Can create event types',
                    'category': 'event_management'
                }
            )
            manage_bookings_perm, _ = Permission.objects.get_or_create(
                codename='can_manage_bookings',
                defaults={
                    'name': 'Manage Bookings',
                    'description': 'Can manage all bookings',
                    'category': 'event_management'
                }
            )
            
            # Add permissions to the role
            default_role.role_permissions.add(create_events_perm, manage_bookings_perm)
        
        user.roles.add(default_role)
        
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    remember_me = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError('Invalid credentials')
            
            # Check if account is locked
            if user.is_account_locked():
                raise serializers.ValidationError('Account is temporarily locked due to multiple failed login attempts')
            
            # Check account status
            if user.account_status != 'active':
                if user.account_status == 'pending_verification':
                    raise serializers.ValidationError('Please verify your email address before logging in')
                elif user.account_status == 'suspended':
                    raise serializers.ValidationError('Your account has been suspended')
                else:
                    raise serializers.ValidationError('Your account is not active')
            
            # Authenticate user
            user = authenticate(username=email, password=password)
            if not user:
                # Increment failed login attempts
                try:
                    user_obj = User.objects.get(email=email)
                    user_obj.failed_login_attempts += 1
                    if user_obj.failed_login_attempts >= 5:
                        user_obj.lock_account()
                    user_obj.save(update_fields=['failed_login_attempts'])
                except User.DoesNotExist:
                    pass
                
                raise serializers.ValidationError('Invalid credentials')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')
            
            # Reset failed login attempts on successful login
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.save(update_fields=['failed_login_attempts'])
            
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include email and password')
        
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        
        # Validate new password strength
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect")
        return value


class ForcedPasswordChangeSerializer(serializers.Serializer):
    """Serializer for forced password change (no old password required)."""
    new_password = serializers.CharField(min_length=8)
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        
        # Validate new password strength
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        # Check password history to prevent reuse
        user = self.context['request'].user
        from django.contrib.auth.hashers import check_password
        
        recent_passwords = user.password_history.order_by('-created_at')[:5]
        for old_password in recent_passwords:
            if check_password(attrs['new_password'], old_password.password_hash):
                raise serializers.ValidationError({'new_password': ['Cannot reuse recent passwords']})
        
        return attrs
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            User.objects.get(email=value, is_active=True)
        except User.DoesNotExist:
            # Don't reveal if email exists or not for security
            pass
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Validate password strength
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        # Validate token
        try:
            token = PasswordResetToken.objects.get(token=attrs['token'])
            if not token.is_valid():
                raise serializers.ValidationError("Token is invalid or expired")
            attrs['reset_token'] = token
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Token is invalid or expired")
        
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    
    def validate_token(self, value):
        try:
            token = EmailVerificationToken.objects.get(token=value)
            if not token.is_valid():
                raise serializers.ValidationError("Token is invalid or expired")
            return token
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Token is invalid or expired")


class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'display_name', 'bio', 'profile_picture', 'phone', 'website',
            'company', 'job_title', 'timezone_name', 'language',
            'date_format', 'time_format', 'brand_color', 'brand_logo',
            'public_profile', 'show_phone', 'show_email'
        ]


class InvitationSerializer(serializers.ModelSerializer):
    invited_by_name = serializers.CharField(source='invited_by.get_full_name', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    
    class Meta:
        model = Invitation
        fields = [
            'id', 'invited_email', 'role', 'role_name', 'message',
            'status', 'invited_by_name', 'created_at', 'expires_at'
        ]
        read_only_fields = ['id', 'status', 'created_at', 'expires_at']


class InvitationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['invited_email', 'role', 'message']
    
    def validate_invited_email(self, value):
        # Check if user already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists")
        
        # Check if there's already a pending invitation
        if Invitation.objects.filter(
            invited_email=value,
            invited_by=self.context['request'].user,
            status='pending'
        ).exists():
            raise serializers.ValidationError("A pending invitation already exists for this email")
        
        return value


class InvitationResponseSerializer(serializers.Serializer):
    token = serializers.CharField()
    action = serializers.ChoiceField(choices=['accept', 'decline'])
    
    # Fields for new user registration (if accepting and user doesn't exist)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    password = serializers.CharField(required=False, min_length=8)
    password_confirm = serializers.CharField(required=False)
    
    def validate(self, attrs):
        # Validate token
        try:
            invitation = Invitation.objects.get(token=attrs['token'])
            if not invitation.is_valid():
                raise serializers.ValidationError("Invitation is invalid or expired")
            attrs['invitation'] = invitation
        except Invitation.DoesNotExist:
            raise serializers.ValidationError("Invitation is invalid or expired")
        
        # If accepting and user doesn't exist, validate registration fields
        if attrs['action'] == 'accept':
            try:
                User.objects.get(email=invitation.invited_email)
            except User.DoesNotExist:
                # User doesn't exist, validate registration fields
                required_fields = ['first_name', 'last_name', 'password', 'password_confirm']
                for field in required_fields:
                    if not attrs.get(field):
                        raise serializers.ValidationError(f"{field} is required for new users")
                
                if attrs['password'] != attrs['password_confirm']:
                    raise serializers.ValidationError("Passwords don't match")
                
                try:
                    validate_password(attrs['password'])
                except ValidationError as e:
                    raise serializers.ValidationError({'password': e.messages})
        
        return attrs


class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user_email', 'action', 'action_display', 'description',
            'ip_address', 'user_agent', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class UserSessionSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(source='is_expired', read_only=True)
    location = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'session_key', 'ip_address', 'country', 'city', 'location', 
            'user_agent', 'device_info',
            'created_at', 'last_activity', 'expires_at', 'is_active',
            'is_current', 'is_expired'
        ]
        read_only_fields = ['id', 'created_at', 'last_activity']
    
    def get_is_current(self, obj):
        request = self.context.get('request')
        if request and hasattr(request, 'session'):
            return obj.session_key == request.session.session_key
        return False
    
    def get_location(self, obj):
        if obj.country and obj.city:
            return f"{obj.city}, {obj.country}"
        elif obj.country:
            return obj.country
        return "Unknown"


class PublicProfileSerializer(serializers.ModelSerializer):
    """Serializer for public profile view (limited fields)."""
    organizer_name = serializers.CharField(source='display_name', read_only=True)
    
    class Meta:
        model = Profile
        fields = [
            'organizer_slug', 'organizer_name', 'bio', 'profile_picture',
            'website', 'company', 'timezone_name', 'brand_color'
        ]
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        
        # Only show fields that user has made public
        if not instance.public_profile:
            return {'organizer_slug': data['organizer_slug']}
        
        # Filter based on privacy settings
        if not instance.show_email and 'email' in data:
            data.pop('email')
        
        return data


class MFADeviceSerializer(serializers.ModelSerializer):
    device_type_display = serializers.CharField(source='get_device_type_display', read_only=True)
    
    class Meta:
        model = MFADevice
        fields = [
            'id', 'device_type', 'device_type_display', 'name', 'phone_number',
            'is_active', 'is_primary', 'last_used_at', 'created_at'
        ]
        read_only_fields = ['id', 'last_used_at', 'created_at']


class MFASetupSerializer(serializers.Serializer):
    """Serializer for MFA setup initiation."""
    device_type = serializers.ChoiceField(choices=MFADevice.DEVICE_TYPES)
    device_name = serializers.CharField(max_length=100)
    phone_number = serializers.CharField(max_length=20, required=False)
    
    def validate(self, attrs):
        if attrs['device_type'] == 'sms' and not attrs.get('phone_number'):
            raise serializers.ValidationError("Phone number is required for SMS devices")
        
        # Validate phone number format if provided
        if attrs.get('phone_number'):
            from .utils import validate_phone_number
            if not validate_phone_number(attrs['phone_number']):
                raise serializers.ValidationError("Invalid phone number format")
        
        return attrs


class MFAVerificationSerializer(serializers.Serializer):
    """Serializer for MFA token verification."""
    otp_code = serializers.CharField(max_length=10)
    device_id = serializers.UUIDField(required=False)
    
    def validate_otp_code(self, value):
        """Validate OTP code format."""
        if not value.isdigit():
            raise serializers.ValidationError("OTP code must contain only digits")
        if len(value) != 6:
            raise serializers.ValidationError("OTP code must be 6 digits")
        return value


class SAMLConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SAMLConfiguration
        fields = [
            'id', 'organization_name', 'organization_domain', 'entity_id',
            'sso_url', 'slo_url', 'email_attribute', 'first_name_attribute',
            'last_name_attribute', 'role_attribute', 'is_active',
            'auto_provision_users', 'default_role', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'x509_cert': {'write_only': True}
        }


class OIDCConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = OIDCConfiguration
        fields = [
            'id', 'organization_name', 'organization_domain', 'issuer',
            'client_id', 'scopes', 'email_claim', 'first_name_claim',
            'last_name_claim', 'role_claim', 'is_active',
            'auto_provision_users', 'default_role', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'client_secret': {'write_only': True}
        }


class SSOInitiateSerializer(serializers.Serializer):
    """Serializer for SSO initiation."""
    sso_type = serializers.ChoiceField(choices=['saml', 'oidc'])
    organization_domain = serializers.CharField(max_length=100)
    redirect_url = serializers.URLField(required=False)
users.views


# users views.py 

from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from django.contrib.auth import login
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.hashers import make_password
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from .models import (
    User, Profile, Role, Permission, EmailVerificationToken, PasswordResetToken,
    Invitation, AuditLog, UserSession, PasswordHistory, MFADevice,
    SAMLConfiguration, OIDCConfiguration, SSOSession
)
from .serializers import (
    UserSerializer, UserRegistrationSerializer, LoginSerializer, PermissionSerializer,
    ProfileSerializer, ProfileUpdateSerializer, ChangePasswordSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    EmailVerificationSerializer, ResendVerificationSerializer,
    InvitationSerializer, InvitationCreateSerializer, InvitationResponseSerializer,
    AuditLogSerializer, UserSessionSerializer, PublicProfileSerializer,
    RoleSerializer, MFADeviceSerializer, MFASetupSerializer, MFAVerificationSerializer,
    SAMLConfigurationSerializer, OIDCConfigurationSerializer, SSOInitiateSerializer,
    ForcedPasswordChangeSerializer
)
from .tasks import (
    send_welcome_email, send_verification_email, send_password_reset_email, send_invitation_email,
    send_sms_verification, send_sms_mfa_code
)
from .utils import get_client_ip, get_user_agent, create_audit_log, get_geolocation_from_ip


class RegistrationThrottle(AnonRateThrottle):
    scope = 'registration'


class LoginThrottle(AnonRateThrottle):
    scope = 'login'


class PasswordResetThrottle(AnonRateThrottle):
    scope = 'password_reset'


@method_decorator(ratelimit(key='ip', rate='5/m', method='POST'), name='post')
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [RegistrationThrottle]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            
            # Create audit log
            create_audit_log(
                user=user,
                action='registration',
                description=f"User registered with email {user.email}",
                request=request
            )
            
            # Send verification email
            send_verification_email.delay(user.id)
            
            # Send welcome email
            send_welcome_email.delay(user.id)
        
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key,
            'message': 'Registration successful. Please check your email to verify your account.'
        }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([LoginThrottle])
@ratelimit(key='ip', rate='10/m', method='POST')
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data['user']
    remember_me = serializer.validated_data.get('remember_me', False)
    
    # Check if password has expired
    if user.password_expires_at and user.password_expires_at <= timezone.now():
        user.account_status = 'password_expired'
        user.save(update_fields=['account_status'])
        
        # Trigger password reset email
        send_password_reset_email.delay(user.id, "Your password has expired. Please reset it to continue.")
        
        return Response({
            'error': 'Password has expired. A password reset email has been sent.',
            'code': 'password_expired'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Update last login IP
    user.last_login_ip = get_client_ip(request)
    user.save(update_fields=['last_login_ip'])
    
    # Create or get token
    token, created = Token.objects.get_or_create(user=user)
    
    # Create user session
    session_key = request.session.session_key
    if not session_key:
        request.session.create()
        session_key = request.session.session_key
    
    # Get geolocation data
    ip_address = get_client_ip(request)
    geo_data = get_geolocation_from_ip(ip_address)
    
    # Set session expiry based on remember_me
    if remember_me:
        request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days
    else:
        request.session.set_expiry(0)  # Browser session
    
    # Create session record
    UserSession.objects.update_or_create(
        user=user,
        session_key=session_key,
        defaults={
            'ip_address': ip_address,
            'country': geo_data['country'],
            'city': geo_data['city'],
            'user_agent': get_user_agent(request),
            'expires_at': timezone.now() + timezone.timedelta(days=30 if remember_me else 1),
            'is_active': True
        }
    )
    
    # Create audit log
    create_audit_log(
        user=user,
        action='login',
        description=f"User logged in from {get_client_ip(request)}",
        request=request
    )
    
    login(request, user)
    
    return Response({
        'user': UserSerializer(user).data,
        'token': token.key
    })


@api_view(['POST'])
def logout_view(request):
    user = request.user if request.user.is_authenticated else None
    
    # Revoke token
    if user:
        try:
            request.user.auth_token.delete()
        except:
            pass
        
        # Delete Django session
        if hasattr(request, 'session') and request.session.session_key:
            request.session.delete()
        
        # Deactivate session
        session_key = request.session.session_key
        if session_key:
            UserSession.objects.filter(
                user=user,
                session_key=session_key
            ).update(is_active=False)
        
        # Create audit log
        create_audit_log(
            user=user,
            action='logout',
            description=f"User logged out from {get_client_ip(request)}",
            request=request
        )
    
    return Response({'message': 'Successfully logged out'})


class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        profile, created = Profile.objects.get_or_create(user=self.request.user)
        return profile
    
    def get_serializer_class(self):
        if self.request.method in ['PATCH', 'PUT']:
            return ProfileUpdateSerializer
        return ProfileSerializer
    
    def perform_update(self, serializer):
        serializer.save()
        
        # Create audit log
        create_audit_log(
            user=self.request.user,
            action='profile_updated',
            description="User updated their profile",
            request=self.request,
            content_object=serializer.instance
        )


class PublicProfileView(generics.RetrieveAPIView):
    """Public view for user profiles by organizer slug."""
    serializer_class = PublicProfileSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'organizer_slug'
    lookup_url_kwarg = 'organizer_slug'
    
    def get_queryset(self):
        return Profile.objects.filter(
            user__is_organizer=True,
            user__is_active=True,
            user__account_status='active'
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    
    user = request.user
    new_password = serializer.validated_data['new_password']
    
    # Check password history
    password_hash = make_password(new_password)
    recent_passwords = PasswordHistory.objects.filter(user=user).order_by('-created_at')[:5]
    
    for old_password in recent_passwords:
        if user.check_password(new_password):
            return Response(
                {'error': 'Cannot reuse recent passwords'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Update password
    user.set_password(new_password)
    user.password_changed_at = timezone.now()
    user.save(update_fields=['password', 'password_changed_at'])
    
    # Save to password history
    PasswordHistory.objects.create(user=user, password_hash=password_hash)
    
    # Revoke all existing tokens
    Token.objects.filter(user=user).delete()
    
    # Deactivate all sessions except current
    current_session = request.session.session_key
    UserSession.objects.filter(user=user).exclude(session_key=current_session).update(is_active=False)
    
    # Create new token
    token = Token.objects.create(user=user)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='password_changed',
        description="User changed their password",
        request=request,
        content_object=user
    )
    
    return Response({
        'message': 'Password changed successfully',
        'token': token.key
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def force_password_change(request):
    """Force password change for users in grace period."""
    user = request.user
    
    # Only allow if user is in password expired grace period
    if user.account_status != 'password_expired_grace_period':
        return Response(
            {'error': 'Forced password change is only available during grace period'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = ForcedPasswordChangeSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    
    new_password = serializer.validated_data['new_password']
    
    # Update password (this will also update password_changed_at and password_expires_at)
    user.set_password(new_password)
    user.account_status = 'active'  # Restore active status
    user.save()
    
    # Save to password history
    from django.contrib.auth.hashers import make_password
    password_hash = make_password(new_password)
    PasswordHistory.objects.create(user=user, password_hash=password_hash)
    
    # Revoke all existing tokens except current
    current_token = getattr(request.auth, 'key', None)
    Token.objects.filter(user=user).exclude(key=current_token).delete()
    
    # Deactivate all sessions except current
    current_session = request.session.session_key
    UserSession.objects.filter(user=user).exclude(session_key=current_session).update(is_active=False)
    
    # Create new token if current one was revoked
    token, created = Token.objects.get_or_create(user=user)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='forced_password_change',
        description="User completed forced password change during grace period",
        request=request,
        content_object=user
    )
    
    return Response({
        'message': 'Password changed successfully. Your account is now active.',
        'token': token.key
    })
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([PasswordResetThrottle])
@ratelimit(key='ip', rate='3/h', method='POST')
def request_password_reset(request):
    serializer = PasswordResetRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    email = serializer.validated_data['email']
    
    try:
        user = User.objects.get(email=email, is_active=True)
        
        # Invalidate existing tokens
        PasswordResetToken.objects.filter(user=user, used_at__isnull=True).update(
            used_at=timezone.now()
        )
        
        # Create new token
        reset_token = PasswordResetToken.objects.create(
            user=user,
            created_ip=get_client_ip(request)
        )
        
        # Send reset email
        send_password_reset_email.delay(user.id, reset_token.token)
        
        # Create audit log
        create_audit_log(
            user=user,
            action='password_reset_requested',
            description=f"Password reset requested from {get_client_ip(request)}",
            request=request,
            content_object=user
        )
        
    except User.DoesNotExist:
        # Don't reveal if email exists
        pass
    
    return Response({
        'message': 'If an account with that email exists, a password reset link has been sent.'
    })


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def confirm_password_reset(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    reset_token = serializer.validated_data['reset_token']
    new_password = serializer.validated_data['new_password']
    
    user = reset_token.user
    
    # Update password
    user.set_password(new_password)
    user.password_changed_at = timezone.now()
    user.failed_login_attempts = 0
    user.locked_until = None
    user.save(update_fields=['password', 'password_changed_at', 'failed_login_attempts', 'locked_until'])
    
    # Mark token as used
    reset_token.mark_as_used(get_client_ip(request))
    
    # Save to password history
    password_hash = make_password(new_password)
    PasswordHistory.objects.create(user=user, password_hash=password_hash)
    
    # Revoke all tokens and sessions
    Token.objects.filter(user=user).delete()
    UserSession.objects.filter(user=user).update(is_active=False)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='password_reset_completed',
        description=f"Password reset completed from {get_client_ip(request)}",
        request=request,
        content_object=user
    )
    
    return Response({'message': 'Password reset successfully'})


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_email(request):
    serializer = EmailVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    token = serializer.validated_data['token']
    user = token.user
    
    # Update user
    if token.token_type == 'email_verification':
        user.is_email_verified = True
        user.account_status = 'active'
    elif token.token_type == 'email_change':
        user.email = token.email
        user.is_email_verified = True
    
    user.save()
    
    # Mark token as used
    token.mark_as_used()
    
    # Create audit log
    create_audit_log(
        user=user,
        action='email_verified',
        description=f"Email verified: {token.email}",
        request=request,
        content_object=user
    )
    
    return Response({'message': 'Email verified successfully'})


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([PasswordResetThrottle])
def resend_verification(request):
    serializer = ResendVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    email = serializer.validated_data['email']
    
    try:
        user = User.objects.get(email=email, is_active=True)
        if not user.is_email_verified:
            send_verification_email.delay(user.id)
    except User.DoesNotExist:
        pass
    
    return Response({
        'message': 'If an unverified account with that email exists, a verification email has been sent.'
    })


# Role Management Views
class PermissionListView(generics.ListAPIView):
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Permission.objects.all()


class RoleListView(generics.ListAPIView):
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Show all roles for now - in production, you might want to filter based on user permissions
        return Role.objects.all()


# Invitation Views
class InvitationListCreateView(generics.ListCreateAPIView):
    serializer_class = InvitationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Invitation.objects.filter(invited_by=self.request.user)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return InvitationCreateSerializer
        return InvitationSerializer
    
    def perform_create(self, serializer):
        invitation = serializer.save(invited_by=self.request.user)
        
        # Send invitation email
        send_invitation_email.delay(invitation.id)
        
        # Create audit log
        create_audit_log(
            user=self.request.user,
            action='invitation_sent',
            description=f"Invitation sent to {invitation.invited_email}",
            request=self.request,
            content_object=invitation
        )


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def respond_to_invitation(request):
    serializer = InvitationResponseSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    invitation = serializer.validated_data['invitation']
    action = serializer.validated_data['action']
    
    if action == 'decline':
        invitation.decline()
        return Response({'message': 'Invitation declined'})
    
    # Accept invitation
    try:
        user = User.objects.get(email=invitation.invited_email)
    except User.DoesNotExist:
        # Create new user
        user_data = {
            'email': invitation.invited_email,
            'username': invitation.invited_email,
            'first_name': serializer.validated_data['first_name'],
            'last_name': serializer.validated_data['last_name'],
            'is_email_verified': True,
            'account_status': 'active'
        }
        user = User.objects.create_user(**user_data)
        user.set_password(serializer.validated_data['password'])
        user.password_changed_at = timezone.now()
        user.save()
    
    # Accept invitation
    invitation.accept(user)
    
    # Create token
    token, created = Token.objects.get_or_create(user=user)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='invitation_accepted',
        description=f"Accepted invitation from {invitation.invited_by.email}",
        request=request,
        content_object=invitation
    )
    
    return Response({
        'message': 'Invitation accepted successfully',
        'user': UserSerializer(user).data,
        'token': token.key
    })


# Session Management Views
class UserSessionListView(generics.ListAPIView):
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user,
            is_active=True
        ).order_by('-last_activity')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_session(request, session_id):
    session = get_object_or_404(
        UserSession,
        id=session_id,
        user=request.user,
        is_active=True
    )
    
    session.revoke()
    
    # Create audit log
    create_audit_log(
        user=request.user,
        action='session_revoked',
        description=f"Session revoked: {session.ip_address}",
        request=request,
        content_object=session
    )
    
    return Response({'message': 'Session revoked successfully'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_all_sessions(request):
    current_session = request.session.session_key
    
    # Revoke all sessions except current
    UserSession.objects.filter(
        user=request.user,
        is_active=True
    ).exclude(session_key=current_session).update(is_active=False)
    
    # Revoke all tokens except current
    current_token = getattr(request.auth, 'key', None)
    Token.objects.filter(user=request.user).exclude(key=current_token).delete()
    
    # Create audit log
    create_audit_log(
        user=request.user,
        action='all_sessions_revoked',
        description="All sessions revoked except current",
        request=request,
        content_object=request.user
    )
    
    return Response({'message': 'All other sessions revoked successfully'})


# Audit Log Views
class AuditLogListView(generics.ListAPIView):
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return AuditLog.objects.filter(user=self.request.user).order_by('-created_at')


# MFA Management Views
class MFADeviceListView(generics.ListAPIView):
    serializer_class = MFADeviceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return MFADevice.objects.filter(user=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def setup_mfa(request):
    """Initiate MFA setup for user."""
    serializer = MFASetupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    device_type = serializer.validated_data['device_type']
    device_name = serializer.validated_data['device_name']
    phone_number = serializer.validated_data.get('phone_number')
    
    user = request.user
    
    if device_type == 'totp':
        # Generate TOTP secret and QR code
        secret = user.generate_mfa_secret()
        totp_uri = user.get_totp_uri()
        
        # Generate QR code
        import qrcode
        from io import BytesIO
        import base64
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        return Response({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_data}",
            'manual_entry_key': secret,
            'message': 'Scan the QR code with your authenticator app'
        })
    
    elif device_type == 'sms':
        # Send SMS verification code
        from .tasks import send_sms_verification
        send_sms_verification.delay(user.id, phone_number)
        
        return Response({
            'message': 'SMS verification code sent',
            'phone_number': phone_number
        })
    
    return Response({'error': 'Invalid device type'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def verify_mfa_setup(request):
    """Verify and activate MFA setup."""
    serializer = MFAVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    token = serializer.validated_data['token']
    user = request.user
    
    # Verify TOTP token
    if user.verify_totp(token):
        # Enable MFA
        user.is_mfa_enabled = True
        user.save(update_fields=['is_mfa_enabled'])
        
        # Generate backup codes
        backup_codes = user.generate_backup_codes()
        
        # Create MFA device record
        MFADevice.objects.create(
            user=user,
            device_type='totp',
            name='Authenticator App',
            is_active=True,
            is_primary=True
        )
        
        # Create audit log
        create_audit_log(
            user=user,
            action='mfa_enabled',
            description="User enabled MFA",
            request=request,
            content_object=user
        )
        
        return Response({
            'message': 'MFA enabled successfully',
            'backup_codes': backup_codes
        })
    
    return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def disable_mfa(request):
    """Disable MFA for user."""
    password = request.data.get('password')
    
    if not password or not request.user.check_password(password):
        return Response({'error': 'Password required to disable MFA'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    user.disable_mfa()
    
    # Remove MFA devices
    MFADevice.objects.filter(user=user).delete()
    
    # Create audit log
    create_audit_log(
        user=user,
        action='mfa_disabled',
        description="User disabled MFA",
        request=request,
        content_object=user
    )
    
    return Response({'message': 'MFA disabled successfully'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def regenerate_backup_codes(request):
    """Regenerate MFA backup codes."""
    password = request.data.get('password')
    
    if not password or not request.user.check_password(password):
        return Response({'error': 'Password required'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not request.user.is_mfa_enabled:
        return Response({'error': 'MFA is not enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    backup_codes = request.user.generate_backup_codes()
    
    # Create audit log
    create_audit_log(
        user=request.user,
        action='backup_codes_regenerated',
        description="User regenerated MFA backup codes",
        request=request,
        content_object=request.user
    )
    
    return Response({
        'message': 'Backup codes regenerated',
        'backup_codes': backup_codes
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def resend_sms_otp(request):
    """Resend SMS verification code for MFA setup."""
    user = request.user
    
    try:
        # Find the user's active SMS MFA device
        sms_device = MFADevice.objects.get(user=user, device_type='sms', is_active=True)
        
        # Call the task to send the SMS verification
        send_sms_verification.delay(user.id, sms_device.phone_number)
        
        return Response({'message': 'SMS verification code sent successfully'})
    except MFADevice.DoesNotExist:
        return Response(
            {'error': 'No active SMS MFA device found for this user.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': f'Failed to resend SMS verification code: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def send_sms_mfa_code_view(request):
    """Send SMS MFA code during login (used for existing MFA devices)."""
    user = request.user
    device_id = request.data.get('device_id')

    if not device_id:
        return Response({'error': 'Device ID is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Ensure the device belongs to the user and is an active SMS device
        MFADevice.objects.get(id=device_id, user=user, device_type='sms', is_active=True)
        send_sms_mfa_code.delay(user.id, device_id)
        return Response({'message': 'SMS MFA code sent successfully'})
    except MFADevice.DoesNotExist:
        return Response({'error': 'MFA device not found or not active for this user.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': f'Failed to send SMS MFA code: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_sms_mfa_login(request):
    """Verify SMS MFA code during login."""
    # This view would typically be part of the login flow,
    # where the user provides the OTP received via SMS.
    # The actual verification logic would be handled by the LoginSerializer
    # or a dedicated MFA verification serializer.
    # For now, it's a placeholder as the login serializer handles the actual verification.
    return Response({'message': 'SMS MFA login verification endpoint (implementation in serializer)'})


# SSO Configuration Views (Admin only)
class SAMLConfigurationListCreateView(generics.ListCreateAPIView):
    serializer_class = SAMLConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Only allow admins to view/manage SAML configs
        if self.request.user.has_permission('can_manage_sso'):
            return SAMLConfiguration.objects.all()
        return SAMLConfiguration.objects.none()


class SAMLConfigurationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = SAMLConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.has_permission('can_manage_sso'):
            return SAMLConfiguration.objects.all()
        return SAMLConfiguration.objects.none()


class OIDCConfigurationListCreateView(generics.ListCreateAPIView):
    serializer_class = OIDCConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.has_permission('can_manage_sso'):
            return OIDCConfiguration.objects.all()
        return OIDCConfiguration.objects.none()


class OIDCConfigurationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = OIDCConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.has_permission('can_manage_sso'):
            return OIDCConfiguration.objects.all()
        return OIDCConfiguration.objects.none()


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def initiate_sso(request):
    """Initiate SSO login flow."""
    serializer = SSOInitiateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    sso_type = serializer.validated_data['sso_type']
    organization_domain = serializer.validated_data['organization_domain']
    redirect_url = serializer.validated_data.get('redirect_url', '/')
    
    if sso_type == 'saml':
        try:
            saml_config = SAMLConfiguration.objects.get(
                organization_domain=organization_domain,
                is_active=True
            )
            
            # Validate SAML configuration
            from .utils import validate_saml_configuration
            errors = validate_saml_configuration(saml_config)
            if errors:
                return Response(
                    {'error': f'SAML configuration invalid: {", ".join(errors)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Store SAML config ID in session for the authentication process
            request.session['saml_config_id'] = str(saml_config.id)
            request.session['sso_redirect_url'] = redirect_url
            
            # Generate SAML AuthnRequest URL
            from djangosaml2.views import LoginView
            from django.urls import reverse
            
            # Create SAML login URL
            auth_url = reverse('saml2_login')
            if redirect_url != '/':
                auth_url += f"?next={redirect_url}"
            
            return Response({
                'auth_url': auth_url,
                'sso_type': 'saml',
                'organization': saml_config.organization_name
            })
            
        except SAMLConfiguration.DoesNotExist:
            return Response(
                {'error': 'SAML configuration not found for this domain'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    elif sso_type == 'oidc':
        try:
            oidc_config = OIDCConfiguration.objects.get(
                organization_domain=organization_domain,
                is_active=True
            )
            
            # Validate OIDC configuration
            from .utils import validate_oidc_configuration
            errors = validate_oidc_configuration(oidc_config)
            if errors:
                return Response(
                    {'error': f'OIDC configuration invalid: {", ".join(errors)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Store OIDC config info in session
            request.session['oidc_organization_domain'] = organization_domain
            request.session['sso_redirect_url'] = redirect_url
            
            # Generate OIDC authorization URL
            from django.urls import reverse
            auth_url = reverse('oidc_authentication_init')
            if redirect_url != '/':
                auth_url += f"?next={redirect_url}"
            
            return Response({
                'auth_url': auth_url,
                'sso_type': 'oidc',
                'organization': oidc_config.organization_name
            })
            
        except OIDCConfiguration.DoesNotExist:
            return Response(
                {'error': 'OIDC configuration not found for this domain'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    return Response({'error': 'Invalid SSO type'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def sso_logout(request):
    """Handle SSO logout with proper SLO."""
    user = request.user
    
    # Get active SSO sessions
    sso_sessions = SSOSession.objects.filter(
        user=user,
        is_active=True
    )
    
    logout_urls = []
    
    for sso_session in sso_sessions:
        try:
            if sso_session.sso_type == 'saml':
                # Get SAML configuration
                saml_config = SAMLConfiguration.objects.get(
                    organization_name=sso_session.provider_name,
                    is_active=True
                )
                
                if saml_config.slo_url:
                    # Generate SAML SLO URL
                    from django.urls import reverse
                    slo_url = reverse('saml2_logout')
                    logout_urls.append({
                        'type': 'saml',
                        'url': slo_url,
                        'provider': sso_session.provider_name
                    })
            
            elif sso_session.sso_type == 'oidc':
                # Get OIDC configuration
                oidc_config = OIDCConfiguration.objects.get(
                    organization_name=sso_session.provider_name,
                    is_active=True
                )
                
                # Generate OIDC logout URL
                logout_url = f"{oidc_config.issuer}/logout"
                logout_urls.append({
                    'type': 'oidc',
                    'url': logout_url,
                    'provider': sso_session.provider_name
                })
            
            # Deactivate SSO session
            sso_session.is_active = False
            sso_session.save()
            
        except (SAMLConfiguration.DoesNotExist, OIDCConfiguration.DoesNotExist):
            # Configuration no longer exists, just deactivate session
            sso_session.is_active = False
            sso_session.save()
    
    # Create audit log
    create_audit_log(
        user=user,
        action='sso_logout',
        description=f"User initiated SSO logout from {len(sso_sessions)} providers",
        request=request,
        metadata={'logout_urls': logout_urls}
    )
    
    return Response({
        'message': 'SSO logout initiated',
        'logout_urls': logout_urls
    })


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def sso_discovery(request):
    """Discover available SSO providers for a domain."""
    domain = request.GET.get('domain')
    if not domain:
        return Response(
            {'error': 'Domain parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    providers = []
    
    # Check for SAML configurations
    saml_configs = SAMLConfiguration.objects.filter(
        organization_domain=domain,
        is_active=True
    )
    
    for config in saml_configs:
        providers.append({
            'type': 'saml',
            'organization': config.organization_name,
            'domain': config.organization_domain
        })
    
    # Check for OIDC configurations
    oidc_configs = OIDCConfiguration.objects.filter(
        organization_domain=domain,
        is_active=True
    )
    
    for config in oidc_configs:
        providers.append({
            'type': 'oidc',
            'organization': config.organization_name,
            'domain': config.organization_domain
        })
    
    return Response({
        'domain': domain,
        'providers': providers
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def sso_sessions(request):
    """Get user's active SSO sessions."""
    sessions = SSOSession.objects.filter(
        user=request.user,
        is_active=True
    ).order_by('-created_at')
    
    session_data = []
    for session in sessions:
        session_data.append({
            'id': session.id,
            'sso_type': session.sso_type,
            'provider_name': session.provider_name,
            'ip_address': session.ip_address,
            'created_at': session.created_at,
            'last_activity': session.last_activity,
            'expires_at': session.expires_at
        })
    
    return Response({
        'sessions': session_data
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_sso_session(request, session_id):
    """Revoke a specific SSO session."""
    try:
        session = SSOSession.objects.get(
            id=session_id,
            user=request.user,
            is_active=True
        )
        
        session.is_active = False
        session.save()
        
        # Create audit log
        create_audit_log(
            user=request.user,
            action='sso_session_revoked',
            description=f"SSO session revoked: {session.provider_name}",
            request=request,
            content_object=session
        )   
        
        return Response({'message': 'SSO session revoked successfully'})
        
    except SSOSession.DoesNotExist:
        return Response(
            {'error': 'SSO session not found'},
            status=status.HTTP_404_NOT_FOUND
        )


# users tasks.py
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from .models import User, EmailVerificationToken, PasswordResetToken, Invitation, UserSession
from datetime import timedelta


@shared_task
def send_welcome_email(user_id):
    """Send welcome email to new users."""
    try:
        user = User.objects.get(id=user_id)
        
        subject = 'Welcome to Calendly Clone!'
        html_message = render_to_string('emails/welcome.html', {
            'user': user,
            'site_name': 'Calendly Clone',
            'site_url': settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else 'http://localhost:3000'
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Welcome email sent to {user.email}"
    except User.DoesNotExist:
        return f"User with id {user_id} not found"
    except Exception as e:
        return f"Failed to send welcome email: {str(e)}"


@shared_task
def send_verification_email(user_id):
    """Send email verification email."""
    try:
        user = User.objects.get(id=user_id)
        
        # Invalidate existing tokens
        EmailVerificationToken.objects.filter(
            user=user,
            token_type='email_verification',
            used_at__isnull=True
        ).update(used_at=timezone.now())
        
        # Create new token
        token = EmailVerificationToken.objects.create(
            user=user,
            email=user.email,
            token_type='email_verification'
        )
        
        verification_url = f"{settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else 'http://localhost:3000'}/verify-email?token={token.token}"
        
        subject = 'Verify your email address'
        html_message = render_to_string('emails/email_verification.html', {
            'user': user,
            'verification_url': verification_url,
            'site_name': 'Calendly Clone'
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Verification email sent to {user.email}"
    except User.DoesNotExist:
        return f"User with id {user_id} not found"
    except Exception as e:
        return f"Failed to send verification email: {str(e)}"


@shared_task
def send_password_reset_email(user_id, token_or_message=None):
    """Send password reset email."""
    try:
        user = User.objects.get(id=user_id)
        
        # Handle both token-based reset and password expiry notification
        if token_or_message and len(token_or_message) > 50:  # Assume it's a message if long
            # This is a password expiry notification
            subject = 'Password Expired - Reset Required'
            message = token_or_message
            reset_url = f"{settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else 'http://localhost:3000'}/request-password-reset"
        else:
            # This is a normal password reset with token
            subject = 'Reset your password'
            message = f"We received a request to reset the password for your {settings.SITE_NAME if hasattr(settings, 'SITE_NAME') else 'Calendly Clone'} account."
            reset_url = f"{settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else 'http://localhost:3000'}/reset-password?token={token_or_message}"
        
        html_message = render_to_string('emails/password_reset.html', {
            'user': user,
            'reset_url': reset_url,
            'message': message,
            'site_name': 'Calendly Clone'
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Password reset email sent to {user.email}"
    except User.DoesNotExist:
        return f"User with id {user_id} not found"
    except Exception as e:
        return f"Failed to send password reset email: {str(e)}"


@shared_task
def send_invitation_email(invitation_id):
    """Send team invitation email."""
    try:
        invitation = Invitation.objects.get(id=invitation_id)
        
        invitation_url = f"{settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else 'http://localhost:3000'}/invitation?token={invitation.token}"
        
        subject = f'You\'re invited to join {invitation.invited_by.get_full_name()}\'s team'
        html_message = render_to_string('emails/invitation.html', {
            'invitation': invitation,
            'invitation_url': invitation_url,
            'site_name': 'Calendly Clone'
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [invitation.invited_email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Invitation email sent to {invitation.invited_email}"
    except Invitation.DoesNotExist:
        return f"Invitation with id {invitation_id} not found"
    except Exception as e:
        return f"Failed to send invitation email: {str(e)}"


@shared_task
def cleanup_expired_tokens():
    """Clean up expired tokens."""
    now = timezone.now()
    
    # Clean up expired email verification tokens
    expired_email_tokens = EmailVerificationToken.objects.filter(
        expires_at__lt=now,
        used_at__isnull=True
    )
    email_count = expired_email_tokens.count()
    expired_email_tokens.delete()
    
    # Clean up expired password reset tokens
    expired_password_tokens = PasswordResetToken.objects.filter(
        expires_at__lt=now,
        used_at__isnull=True
    )
    password_count = expired_password_tokens.count()
    expired_password_tokens.delete()
    
    # Clean up expired invitations
    expired_invitations = Invitation.objects.filter(
        expires_at__lt=now,
        status='pending'
    )
    invitation_count = expired_invitations.count()
    expired_invitations.update(status='expired')
    
    # Clean up old inactive sessions
    old_sessions = UserSession.objects.filter(
        is_active=False,
        last_activity__lt=now - timedelta(days=30)
    )
    session_count = old_sessions.count()
    old_sessions.delete()
    
    return f"Cleaned up {email_count} email tokens, {password_count} password tokens, {invitation_count} invitations, {session_count} old sessions"


@shared_task
def create_default_permissions():
    """Create default permissions for the system."""
    from .models import Permission, Role
    
    default_permissions = [
        # User management
        ('can_view_users', 'View Users', 'Can view user list and details', 'user_management'),
        ('can_create_users', 'Create Users', 'Can create new user accounts', 'user_management'),
        ('can_edit_users', 'Edit Users', 'Can edit user accounts', 'user_management'),
        ('can_delete_users', 'Delete Users', 'Can delete user accounts', 'user_management'),
        
        # Event management
        ('can_view_events', 'View Events', 'Can view event types and bookings', 'event_management'),
        ('can_create_events', 'Create Events', 'Can create event types', 'event_management'),
        ('can_edit_events', 'Edit Events', 'Can edit event types', 'event_management'),
        ('can_delete_events', 'Delete Events', 'Can delete event types', 'event_management'),
        ('can_manage_bookings', 'Manage Bookings', 'Can manage all bookings', 'event_management'),
        
        # System administration
        ('can_view_admin', 'View Admin', 'Can access admin interface', 'administration'),
        ('can_manage_roles', 'Manage Roles', 'Can create and assign roles', 'administration'),
        ('can_view_audit_logs', 'View Audit Logs', 'Can view system audit logs', 'administration'),
        ('can_manage_integrations', 'Manage Integrations', 'Can manage external integrations', 'administration'),
        
        # Billing and subscriptions
        ('can_view_billing', 'View Billing', 'Can view billing information', 'billing'),
        ('can_manage_billing', 'Manage Billing', 'Can manage billing and subscriptions', 'billing'),
        
        # Reports and analytics
        ('can_view_reports', 'View Reports', 'Can view reports and analytics', 'reporting'),
        ('can_export_data', 'Export Data', 'Can export system data', 'reporting'),
    ]
    
    created_count = 0
    for codename, name, description, category in default_permissions:
        permission, created = Permission.objects.get_or_create(
            codename=codename,
            defaults={
                'name': name,
                'description': description,
                'category': category
            }
        )
        if created:
            created_count += 1
    
    return f"Created {created_count} default permissions"


@shared_task
def cleanup_inactive_users():
    """Clean up inactive users who haven't verified email after 30 days."""
    cutoff_date = timezone.now() - timedelta(days=30)
    
    inactive_users = User.objects.filter(
        is_email_verified=False,
        account_status='pending_verification',
        date_joined__lt=cutoff_date
    )
    
    count = inactive_users.count()
    inactive_users.delete()
    
    return f"Cleaned up {count} inactive users"


@shared_task
def unlock_locked_accounts():
    """Unlock accounts that have passed their lock duration."""
    now = timezone.now()
    
    locked_users = User.objects.filter(
        locked_until__lt=now,
        locked_until__isnull=False
    )
    
    count = locked_users.count()
    locked_users.update(
        locked_until=None,
        failed_login_attempts=0
    )
    
    return f"Unlocked {count} accounts"


@shared_task
def send_password_expiry_warning(user_id):
    """Send password expiry warning email."""
    try:
        user = User.objects.get(id=user_id)
        
        if not user.password_expires_at:
            return "User password does not expire"
        
        days_until_expiry = (user.password_expires_at - timezone.now()).days
        
        subject = f'Your password expires in {days_until_expiry} days'
        html_message = render_to_string('emails/password_expiry_warning.html', {
            'user': user,
            'days_until_expiry': days_until_expiry,
            'change_password_url': f"{settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else 'http://localhost:3000'}/change-password",
            'site_name': 'Calendly Clone'
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Password expiry warning sent to {user.email}"
    except User.DoesNotExist:
        return f"User with id {user_id} not found"
    except Exception as e:
        return f"Failed to send password expiry warning: {str(e)}"


@shared_task
def check_password_expiries_and_warn():
    """Check for passwords nearing expiry and send warnings."""
    from django.conf import settings
    from datetime import timedelta
    
    if not hasattr(settings, 'PASSWORD_EXPIRY_DAYS') or settings.PASSWORD_EXPIRY_DAYS <= 0:
        return "Password expiry is disabled"
    
    warning_days = getattr(settings, 'PASSWORD_EXPIRY_WARNING_DAYS', 7)
    warning_threshold = timezone.now() + timedelta(days=warning_days)
    
    # Find users whose passwords will expire within the warning period
    users_to_warn = User.objects.filter(
        is_active=True,
        account_status='active',
        password_expires_at__lte=warning_threshold,
        password_expires_at__gt=timezone.now()
    )
    
    warned_count = 0
    for user in users_to_warn:
        # Check if we've already sent a warning recently (within last 24 hours)
        recent_warning = user.audit_logs.filter(
            action='password_expiry_warning_sent',
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).exists()
        
        if not recent_warning:
            send_password_expiry_warning.delay(user.id)
            
            # Create audit log
            from .utils import create_audit_log
            create_audit_log(
                user=user,
                action='password_expiry_warning_sent',
                description=f"Password expiry warning sent - expires in {user.days_until_password_expiry()} days",
                metadata={'days_until_expiry': user.days_until_password_expiry()}
            )
            warned_count += 1
    
    return f"Sent password expiry warnings to {warned_count} users"


@shared_task
def cleanup_expired_grace_periods():
    """Clean up users whose grace period has expired."""
    from django.conf import settings
    from datetime import timedelta
    
    if not hasattr(settings, 'PASSWORD_EXPIRY_DAYS') or settings.PASSWORD_EXPIRY_DAYS <= 0:
        return "Password expiry is disabled"
    
    grace_period_hours = getattr(settings, 'PASSWORD_EXPIRY_GRACE_PERIOD_HOURS', 24)
    
    # Find users whose grace period has expired
    expired_grace_users = User.objects.filter(
        account_status='password_expired_grace_period',
        password_expires_at__lt=timezone.now() - timedelta(hours=grace_period_hours)
    )
    
    count = expired_grace_users.count()
    
    # Move them to fully expired status
    expired_grace_users.update(account_status='password_expired')
    
    # Send password reset emails for these users
    for user in expired_grace_users:
        send_password_reset_email.delay(
            user.id, 
            "Your password has expired and the grace period has ended. Please reset your password to regain access."
        )
        
        # Create audit log
        from .utils import create_audit_log
        create_audit_log(
            user=user,
            action='password_grace_period_expired',
            description="Password grace period expired, account moved to password_expired status",
            metadata={'grace_period_hours': grace_period_hours}
        )
    
    return f"Processed {count} users whose grace period expired"


@shared_task
def send_sms_verification(user_id, phone_number):
    """Send SMS verification code for MFA setup."""
    try:
        from twilio.rest import Client
        from django.conf import settings
        from django.core.cache import cache
        import random
        
        user = User.objects.get(id=user_id)
        
        # Generate 6-digit code
        code = f"{random.randint(100000, 999999)}"
        
        # Store code in cache for 5 minutes
        cache_key = f"sms_otp_{user_id}"
        cache.set(cache_key, code, timeout=300)  # 5 minutes
        
        # Send SMS using Twilio
        if hasattr(settings, 'TWILIO_ACCOUNT_SID') and hasattr(settings, 'TWILIO_AUTH_TOKEN'):
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            
            message = client.messages.create(
                body=f"Your Calendly Clone verification code is: {code}",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            
            # Create audit log
            from .utils import create_audit_log
            create_audit_log(
                user=user,
                action='sms_otp_sent',
                description=f"SMS OTP sent to {phone_number}",
                metadata={'phone_number': phone_number, 'message_sid': message.sid}
            )
            
            return f"SMS sent to {phone_number}: {message.sid}"
        else:
            # For development, just log the code
            print(f"SMS verification code for {phone_number}: {code}")
            return f"SMS verification code (dev mode): {code}"
            
    except User.DoesNotExist:
        return f"User {user_id} not found"
    except Exception as e:
        return f"Failed to send SMS: {str(e)}"


@shared_task
def send_sms_mfa_code(user_id, device_id):
    """Send SMS MFA code during login."""
    try:
        from twilio.rest import Client
        from django.conf import settings
        from django.core.cache import cache
        from .models import MFADevice
        import random
        
        user = User.objects.get(id=user_id)
        device = MFADevice.objects.get(id=device_id, user=user, device_type='sms', is_active=True)
        
        # Check rate limiting
        if not device.can_attempt_verification():
            return f"Rate limit exceeded for device {device_id}"
        
        # Generate 6-digit code
        code = f"{random.randint(100000, 999999)}"
        
        # Store code in cache for 5 minutes
        cache_key = f"sms_mfa_{user_id}_{device_id}"
        cache.set(cache_key, code, timeout=300)  # 5 minutes
        
        # Send SMS using Twilio
        if hasattr(settings, 'TWILIO_ACCOUNT_SID') and hasattr(settings, 'TWILIO_AUTH_TOKEN'):
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            
            message = client.messages.create(
                body=f"Your Calendly Clone login code is: {code}",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=device.phone_number
            )
            
            # Create audit log
            from .utils import create_audit_log
            create_audit_log(
                user=user,
                action='sms_mfa_sent',
                description=f"SMS MFA code sent to {device.phone_number}",
                metadata={'phone_number': device.phone_number, 'message_sid': message.sid, 'device_id': str(device_id)}
            )
            
            return f"SMS MFA code sent to {device.phone_number}: {message.sid}"
        else:
            # For development, just log the code
            print(f"SMS MFA code for {device.phone_number}: {code}")
            return f"SMS MFA code (dev mode): {code}"
            
    except User.DoesNotExist:
        return f"User {user_id} not found"
    except MFADevice.DoesNotExist:
        return f"MFA device {device_id} not found"
    except Exception as e:
        return f"Failed to send SMS MFA code: {str(e)}"


@shared_task
def cleanup_expired_mfa_sessions():
    """Clean up expired MFA sessions and unused secrets."""
    from datetime import timedelta
    
    # Clean up users who started MFA setup but never completed it
    cutoff_date = timezone.now() - timedelta(hours=1)
    
    incomplete_mfa_users = User.objects.filter(
        mfa_secret__isnull=False,
        is_mfa_enabled=False,
        updated_at__lt=cutoff_date
    )
    
    count = 0
    for user in incomplete_mfa_users:
        user.mfa_secret = ''
        user.save(update_fields=['mfa_secret'])
        count += 1
    
    return f"Cleaned up {count} incomplete MFA setups"



# users validators.py

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import re


class CustomPasswordValidator:
    """
    Custom password validator that enforces:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - No common patterns
    """
    
    def validate(self, password, user=None):
        if not re.search(r'[A-Z]', password):
            raise ValidationError(
                _("Password must contain at least one uppercase letter."),
                code='password_no_upper',
            )
        
        if not re.search(r'[a-z]', password):
            raise ValidationError(
                _("Password must contain at least one lowercase letter."),
                code='password_no_lower',
            )
        
        if not re.search(r'\d', password):
            raise ValidationError(
                _("Password must contain at least one digit."),
                code='password_no_digit',
            )
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                _("Password must contain at least one special character."),
                code='password_no_special',
            )
        
        # Check for common patterns
        common_patterns = [
            r'123',
            r'abc',
            r'qwerty',
            r'password',
            r'admin',
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                raise ValidationError(
                    _("Password contains common patterns that are not allowed."),
                    code='password_common_pattern',
                )
        
        # Check if password is too similar to user information
        if user:
            user_info = [
                user.first_name.lower() if user.first_name else '',
                user.last_name.lower() if user.last_name else '',
                user.email.split('@')[0].lower() if user.email else '',
            ]
            
            for info in user_info:
                if info and len(info) > 2 and info in password.lower():
                    raise ValidationError(
                        _("Password is too similar to your personal information."),
                        code='password_too_similar',
                    )
    
    def get_help_text(self):
        return _(
            "Your password must contain at least one uppercase letter, "
            "one lowercase letter, one digit, and one special character. "
            "It should not contain common patterns or be similar to your personal information."
        )

# users backends.py

"""
Custom authentication backends for SSO integration.
"""
import logging
from django.contrib.auth import get_user_model
from django.utils import timezone
from djangosaml2.backends import Saml2Backend
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from .models import SAMLConfiguration, OIDCConfiguration, SSOSession, Role
from .utils import create_audit_log

logger = logging.getLogger(__name__)
User = get_user_model()


class CustomSAMLBackend(Saml2Backend):
    """
    Custom SAML authentication backend with JIT user provisioning.
    """
    
    def authenticate(self, request, session_info=None, attribute_mapping=None, create_unknown_user=True, **kwargs):
        """
        Authenticate user via SAML assertion with JIT provisioning.
        """
        if session_info is None:
            logger.debug("No SAML session info provided")
            return None
        
        try:
            # Extract attributes from SAML assertion
            attributes = session_info.get('ava', {})
            if not attributes:
                logger.error("No attributes found in SAML assertion")
                return None
            
            # Get SAML configuration based on issuer
            issuer = session_info.get('issuer')
            if not issuer:
                logger.error("No issuer found in SAML assertion")
                return None
            
            # Find matching SAML configuration
            saml_config = self._get_saml_config_by_issuer(issuer)
            if not saml_config:
                logger.error(f"No SAML configuration found for issuer: {issuer}")
                return None
            
            # Extract user information using attribute mapping
            user_info = self._extract_user_info(attributes, saml_config)
            if not user_info.get('email'):
                logger.error("No email found in SAML assertion")
                return None
            
            # Get or create user
            user = self._get_or_create_user(user_info, saml_config, create_unknown_user)
            if not user:
                return None
            
            # Create SSO session record
            self._create_sso_session(user, saml_config, session_info, request)
            
            # Create audit log
            create_audit_log(
                user=user,
                action='saml_login',
                description=f"User logged in via SAML from {saml_config.organization_name}",
                request=request,
                metadata={
                    'saml_config_id': str(saml_config.id),
                    'issuer': issuer,
                    'organization': saml_config.organization_name
                }
            )
            
            return user
            
        except Exception as e:
            logger.error(f"SAML authentication error: {str(e)}")
            return None
    
    def _get_saml_config_by_issuer(self, issuer):
        """Get SAML configuration by issuer/entity ID."""
        try:
            return SAMLConfiguration.objects.get(
                entity_id=issuer,
                is_active=True
            )
        except SAMLConfiguration.DoesNotExist:
            return None
    
    def _extract_user_info(self, attributes, saml_config):
        """Extract user information from SAML attributes."""
        def get_attribute_value(attr_name, default=''):
            """Get first value from SAML attribute list."""
            values = attributes.get(attr_name, [])
            return values[0] if values else default
        
        return {
            'email': get_attribute_value(saml_config.email_attribute),
            'first_name': get_attribute_value(saml_config.first_name_attribute),
            'last_name': get_attribute_value(saml_config.last_name_attribute),
            'role': get_attribute_value(saml_config.role_attribute) if saml_config.role_attribute else None,
        }
    
    def _get_or_create_user(self, user_info, saml_config, create_unknown_user):
        """Get existing user or create new one via JIT provisioning."""
        email = user_info['email'].lower()
        
        try:
            # Try to get existing user
            user = User.objects.get(email=email)
            
            # Update user information if needed
            updated = False
            if user_info['first_name'] and not user.first_name:
                user.first_name = user_info['first_name']
                updated = True
            if user_info['last_name'] and not user.last_name:
                user.last_name = user_info['last_name']
                updated = True
            
            if updated:
                user.save()
            
            return user
            
        except User.DoesNotExist:
            if not create_unknown_user or not saml_config.auto_provision_users:
                logger.info(f"User {email} not found and auto-provisioning disabled")
                return None
            
            # Create new user via JIT provisioning
            user = User.objects.create_user(
                username=email,
                email=email,
                first_name=user_info['first_name'] or '',
                last_name=user_info['last_name'] or '',
                is_email_verified=True,  # Trust SAML assertion
                account_status='active',
                is_organizer=True
            )
            
            # Assign default role
            if saml_config.default_role:
                user.roles.add(saml_config.default_role)
            
            logger.info(f"Created new user via SAML JIT provisioning: {email}")
            return user
    
    def _create_sso_session(self, user, saml_config, session_info, request):
        """Create SSO session record."""
        try:
            session_key = request.session.session_key if request and hasattr(request, 'session') else None
            ip_address = request.META.get('REMOTE_ADDR') if request else None
            user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
            
            SSOSession.objects.create(
                user=user,
                sso_type='saml',
                provider_name=saml_config.organization_name,
                external_session_id=session_info.get('session_index', ''),
                session_key=session_key or '',
                ip_address=ip_address or '127.0.0.1',
                user_agent=user_agent,
                expires_at=timezone.now() + timezone.timedelta(hours=8),
                is_active=True
            )
        except Exception as e:
            logger.error(f"Failed to create SSO session: {str(e)}")


class CustomOIDCBackend(OIDCAuthenticationBackend):
    """
    Custom OIDC authentication backend with JIT user provisioning.
    """
    
    def authenticate(self, request, **kwargs):
        """
        Authenticate user via OIDC with JIT provisioning.
        """
        # Get the organization domain from session or request
        organization_domain = self._get_organization_domain(request)
        if not organization_domain:
            logger.error("No organization domain found for OIDC authentication")
            return None
        
        # Get OIDC configuration
        oidc_config = self._get_oidc_config(organization_domain)
        if not oidc_config:
            logger.error(f"No OIDC configuration found for domain: {organization_domain}")
            return None
        
        # Set dynamic OIDC settings
        self._configure_oidc_settings(oidc_config)
        
        # Call parent authenticate method
        user = super().authenticate(request, **kwargs)
        
        if user:
            # Create SSO session record
            self._create_sso_session(user, oidc_config, request)
            
            # Create audit log
            create_audit_log(
                user=user,
                action='oidc_login',
                description=f"User logged in via OIDC from {oidc_config.organization_name}",
                request=request,
                metadata={
                    'oidc_config_id': str(oidc_config.id),
                    'issuer': oidc_config.issuer,
                    'organization': oidc_config.organization_name
                }
            )
        
        return user
    
    def create_user(self, claims):
        """
        Create user from OIDC claims with JIT provisioning.
        """
        # Get OIDC configuration from thread-local storage or session
        oidc_config = getattr(self, '_current_oidc_config', None)
        if not oidc_config:
            logger.error("No OIDC configuration available for user creation")
            return None
        
        if not oidc_config.auto_provision_users:
            logger.info("Auto-provisioning disabled for OIDC configuration")
            return None
        
        # Extract user information from claims
        email = claims.get(oidc_config.email_claim, '').lower()
        if not email:
            logger.error("No email found in OIDC claims")
            return None
        
        first_name = claims.get(oidc_config.first_name_claim, '')
        last_name = claims.get(oidc_config.last_name_claim, '')
        
        # Create new user
        user = User.objects.create_user(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_email_verified=True,  # Trust OIDC claims
            account_status='active',
            is_organizer=True
        )
        
        # Assign default role
        if oidc_config.default_role:
            user.roles.add(oidc_config.default_role)
        
        logger.info(f"Created new user via OIDC JIT provisioning: {email}")
        return user
    
    def update_user(self, user, claims):
        """
        Update user information from OIDC claims.
        """
        oidc_config = getattr(self, '_current_oidc_config', None)
        if not oidc_config:
            return user
        
        # Update user information
        updated = False
        
        first_name = claims.get(oidc_config.first_name_claim, '')
        if first_name and not user.first_name:
            user.first_name = first_name
            updated = True
        
        last_name = claims.get(oidc_config.last_name_claim, '')
        if last_name and not user.last_name:
            user.last_name = last_name
            updated = True
        
        if updated:
            user.save()
        
        return user
    
    def _get_organization_domain(self, request):
        """Extract organization domain from request."""
        if request and hasattr(request, 'session'):
            return request.session.get('oidc_organization_domain')
        return None
    
    def _get_oidc_config(self, organization_domain):
        """Get OIDC configuration by organization domain."""
        try:
            return OIDCConfiguration.objects.get(
                organization_domain=organization_domain,
                is_active=True
            )
        except OIDCConfiguration.DoesNotExist:
            return None
    
    def _configure_oidc_settings(self, oidc_config):
        """Configure OIDC settings dynamically."""
        from django.conf import settings
        
        # Store config for later use
        self._current_oidc_config = oidc_config
        
        # Set dynamic OIDC settings
        settings.OIDC_RP_CLIENT_ID = oidc_config.client_id
        settings.OIDC_RP_CLIENT_SECRET = oidc_config.client_secret
        settings.OIDC_OP_AUTHORIZATION_ENDPOINT = oidc_config.authorization_endpoint or f"{oidc_config.issuer}/auth"
        settings.OIDC_OP_TOKEN_ENDPOINT = oidc_config.token_endpoint or f"{oidc_config.issuer}/token"
        settings.OIDC_OP_USER_ENDPOINT = oidc_config.userinfo_endpoint or f"{oidc_config.issuer}/userinfo"
        settings.OIDC_OP_JWKS_ENDPOINT = oidc_config.jwks_uri or f"{oidc_config.issuer}/.well-known/jwks.json"
    
    def _create_sso_session(self, user, oidc_config, request):
        """Create SSO session record."""
        try:
            session_key = request.session.session_key if request and hasattr(request, 'session') else None
            ip_address = request.META.get('REMOTE_ADDR') if request else None
            user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
            
            SSOSession.objects.create(
                user=user,
                sso_type='oidc',
                provider_name=oidc_config.organization_name,
                external_session_id='',  # OIDC doesn't typically provide session IDs
                session_key=session_key or '',
                ip_address=ip_address or '127.0.0.1',
                user_agent=user_agent,
                expires_at=timezone.now() + timezone.timedelta(hours=8),
                is_active=True
            )
        except Exception as e:
            logger.error(f"Failed to create OIDC SSO session: {str(e)}")



  # users admin.py


  from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import (
    User, Profile, Role, Permission, EmailVerificationToken, PasswordResetToken,
    Invitation, AuditLog, UserSession, PasswordHistory, MFADevice, SAMLConfiguration, OIDCConfiguration, SSOSession
)


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('name', 'codename', 'category', 'role_count', 'created_at')
    list_filter = ('category', 'created_at')
    search_fields = ('name', 'codename', 'description')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Permission Information', {
            'fields': ('codename', 'name', 'description', 'category')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def role_count(self, obj):
        return obj.roles.count()
    role_count.short_description = 'Roles'
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'role_type', 'parent', 'permission_count', 'is_system_role', 'user_count', 'created_at')
    list_filter = ('role_type', 'is_system_role', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')
    filter_horizontal = ('role_permissions',)
    
    fieldsets = (
        ('Role Information', {
            'fields': ('name', 'role_type', 'parent', 'description', 'is_system_role')
        }),
        ('Permissions', {
            'fields': ('role_permissions',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_count(self, obj):
        return obj.users.count()
    user_count.short_description = 'Users'
    
    def permission_count(self, obj):
        return len(obj.get_all_permissions())
    permission_count.short_description = 'Total Permissions'
    
    def get_readonly_fields(self, request, obj=None):
        readonly_fields = list(self.readonly_fields)
        if obj and obj.is_system_role:
            readonly_fields.extend(['name', 'role_type', 'is_system_role'])
        return readonly_fields


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = (
        'organizer_slug', 'display_name', 'bio', 'profile_picture',
        'phone', 'website', 'company', 'job_title', 'timezone_name',
        'language', 'brand_color', 'public_profile'
    )
    readonly_fields = ('organizer_slug',)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)
    list_display = (
        'email', 'first_name', 'last_name', 'account_status',
        'is_email_verified', 'is_mfa_enabled', 'role_list',
        'last_login', 'date_joined'
    )
    list_filter = (
        'account_status', 'is_email_verified', 'is_mfa_enabled',
        'is_organizer', 'is_active', 'is_staff', 'date_joined'
    )
    search_fields = ('email', 'first_name', 'last_name', 'username')
    ordering = ('-date_joined',)
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Account Status', {
            'fields': (
                'is_organizer', 'is_email_verified', 'is_phone_verified',
                'is_mfa_enabled', 'account_status'
            )
        }),
        ('Security', {
            'fields': (
                'password_changed_at', 'password_expires_at',
                'failed_login_attempts', 'locked_until', 'last_login_ip'
            ),
            'classes': ('collapse',)
        }),
        ('Roles', {
            'fields': ('roles',)
        }),
    )
    
    readonly_fields = BaseUserAdmin.readonly_fields + (
        'password_changed_at', 'failed_login_attempts', 'last_login_ip'
    )
    
    filter_horizontal = ('roles', 'groups', 'user_permissions')
    
    def role_list(self, obj):
        roles = obj.roles.all()[:3]  # Show first 3 roles
        role_names = [role.name for role in roles]
        if obj.roles.count() > 3:
            role_names.append(f'... +{obj.roles.count() - 3} more')
        return ', '.join(role_names) if role_names else 'No roles'
    role_list.short_description = 'Roles'
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('roles')


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'organizer_slug', 'display_name',
        'company', 'timezone_name', 'public_profile', 'created_at'
    )
    list_filter = ('public_profile', 'timezone_name', 'language', 'created_at')
    search_fields = ('user__email', 'organizer_slug', 'display_name', 'company')
    readonly_fields = ('organizer_slug', 'created_at', 'updated_at')
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Profile Information', {
            'fields': (
                'organizer_slug', 'display_name', 'bio', 'profile_picture',
                'phone', 'website', 'company', 'job_title'
            )
        }),
        ('Localization', {
            'fields': ('timezone_name', 'language', 'date_format', 'time_format')
        }),
        ('Branding', {
            'fields': ('brand_color', 'brand_logo')
        }),
        ('Privacy', {
            'fields': ('public_profile', 'show_phone', 'show_email')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'Email'
    user_email.admin_order_field = 'user__email'


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'email', 'token_type', 'is_used', 'created_at', 'expires_at')
    list_filter = ('token_type', 'created_at', 'expires_at')
    search_fields = ('user__email', 'email', 'token')
    readonly_fields = ('token', 'created_at', 'used_at')
    
    fieldsets = (
        ('Token Information', {
            'fields': ('user', 'email', 'token_type', 'token')
        }),
        ('Status', {
            'fields': ('created_at', 'expires_at', 'used_at')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def is_used(self, obj):
        return obj.used_at is not None
    is_used.boolean = True
    is_used.short_description = 'Used'


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'is_used', 'created_at', 'expires_at', 'created_ip')
    list_filter = ('created_at', 'expires_at')
    search_fields = ('user__email', 'token', 'created_ip')
    readonly_fields = ('token', 'created_at', 'used_at')
    
    fieldsets = (
        ('Token Information', {
            'fields': ('user', 'token')
        }),
        ('Status', {
            'fields': ('created_at', 'expires_at', 'used_at')
        }),
        ('Security', {
            'fields': ('created_ip', 'used_ip')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def is_used(self, obj):
        return obj.used_at is not None
    is_used.boolean = True
    is_used.short_description = 'Used'


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__email',)
    readonly_fields = ('user', 'password_hash', 'created_at')
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = (
        'invited_email', 'invited_by_email', 'role_name',
        'status', 'created_at', 'expires_at'
    )
    list_filter = ('status', 'role', 'created_at', 'expires_at')
    search_fields = ('invited_email', 'invited_by__email', 'message')
    readonly_fields = ('token', 'created_at', 'responded_at')
    
    fieldsets = (
        ('Invitation Details', {
            'fields': ('invited_by', 'invited_email', 'role', 'message')
        }),
        ('Status', {
            'fields': ('status', 'token', 'created_at', 'expires_at', 'responded_at')
        }),
        ('Response', {
            'fields': ('accepted_by',)
        }),
    )
    
    def invited_by_email(self, obj):
        return obj.invited_by.email
    invited_by_email.short_description = 'Invited By'
    
    def role_name(self, obj):
        return obj.role.name
    role_name.short_description = 'Role'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'action_display', 'related_object_info', 'ip_address',
        'created_at'
    )
    list_filter = ('action', 'created_at')
    search_fields = ('user__email', 'description', 'ip_address')
    readonly_fields = ('user', 'action', 'description', 'ip_address', 'user_agent', 'session_key', 
                      'content_type', 'object_id', 'related_object', 'metadata', 'created_at')
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Log Information', {
            'fields': ('user', 'action', 'description', 'content_type', 'object_id', 'related_object')
        }),
        ('Context', {
            'fields': ('ip_address', 'user_agent', 'session_key')
        }),
        ('Additional Data', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email if obj.user else 'Anonymous'
    user_email.short_description = 'User'
    
    def action_display(self, obj):
        return obj.get_action_display()
    action_display.short_description = 'Action'
    
    def related_object_info(self, obj):
        if obj.related_object:
            return f"{obj.content_type.model}: {obj.related_object}"
        return "-"
    related_object_info.short_description = 'Related Object'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'ip_address', 'location', 'is_active',
        'created_at', 'last_activity', 'expires_at'
    )
    list_filter = ('is_active', 'created_at', 'last_activity')
    search_fields = ('user__email', 'ip_address', 'session_key', 'country', 'city')
    readonly_fields = ('user', 'session_key', 'ip_address', 'user_agent', 'country', 'city', 'device_info', 'created_at', 'last_activity')
    
    fieldsets = (
        ('Session Information', {
            'fields': ('user', 'session_key', 'is_active')
        }),
        ('Client Information', {
            'fields': ('ip_address', 'country', 'city', 'user_agent', 'device_info')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_activity', 'expires_at')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'
    
    def location(self, obj):
        if obj.country and obj.city:
            return f"{obj.city}, {obj.country}"
        elif obj.country:
            return obj.country
        return "-"
    location.short_description = 'Location'
    
    actions = ['revoke_sessions']
    
    def revoke_sessions(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"Revoked {queryset.count()} sessions.")
    revoke_sessions.short_description = "Revoke selected sessions"


@admin.register(MFADevice)
class MFADeviceAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'device_type', 'name', 'phone_number_masked', 'is_active', 'is_primary', 'verification_attempts', 'last_used_at', 'created_at')
    list_filter = ('device_type', 'is_active', 'is_primary', 'created_at')
    search_fields = ('user__email', 'name', 'phone_number')
    readonly_fields = ('created_at', 'updated_at', 'last_used_at', 'verification_attempts', 'last_verification_attempt')
    
    fieldsets = (
        ('Device Information', {
            'fields': ('user', 'device_type', 'name', 'phone_number')
        }),
        ('Settings', {
            'fields': ('is_active', 'is_primary')
        }),
        ('Security', {
            'fields': ('verification_attempts', 'last_verification_attempt')
        }),
        ('Usage', {
            'fields': ('last_used_at',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def phone_number_masked(self, obj):
        if obj.phone_number:
            return obj.phone_number[-4:].rjust(len(obj.phone_number), '*')
        return '-'
    phone_number_masked.short_description = 'Phone Number'


@admin.register(SAMLConfiguration)
class SAMLConfigurationAdmin(admin.ModelAdmin):
    list_display = ('organization_name', 'organization_domain', 'is_active', 'auto_provision_users', 'created_at')
    list_filter = ('is_active', 'auto_provision_users', 'created_at')
    search_fields = ('organization_name', 'organization_domain', 'entity_id')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Organization', {
            'fields': ('organization_name', 'organization_domain')
        }),
        ('SAML Configuration', {
            'fields': ('entity_id', 'sso_url', 'slo_url', 'x509_cert')
        }),
        ('Attribute Mapping', {
            'fields': ('email_attribute', 'first_name_attribute', 'last_name_attribute', 'role_attribute')
        }),
        ('Settings', {
            'fields': ('is_active', 'auto_provision_users', 'default_role')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        # Validate configuration before saving
        from .utils import validate_saml_configuration
        errors = validate_saml_configuration(obj)
        if errors:
            from django.contrib import messages
            messages.warning(request, f"Configuration warnings: {', '.join(errors)}")
        super().save_model(request, obj, form, change)


@admin.register(OIDCConfiguration)
class OIDCConfigurationAdmin(admin.ModelAdmin):
    list_display = ('organization_name', 'organization_domain', 'issuer', 'is_active', 'auto_provision_users', 'created_at')
    list_filter = ('is_active', 'auto_provision_users', 'created_at')
    search_fields = ('organization_name', 'organization_domain', 'issuer', 'client_id')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Organization', {
            'fields': ('organization_name', 'organization_domain')
        }),
        ('OIDC Configuration', {
            'fields': ('issuer', 'client_id', 'client_secret')
        }),
        ('Endpoints', {
            'fields': ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'),
            'classes': ('collapse',)
        }),
        ('Claims Mapping', {
            'fields': ('scopes', 'email_claim', 'first_name_claim', 'last_name_claim', 'role_claim')
        }),
        ('Settings', {
            'fields': ('is_active', 'auto_provision_users', 'default_role')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        # Validate configuration before saving
        from .utils import validate_oidc_configuration
        errors = validate_oidc_configuration(obj)
        if errors:
            from django.contrib import messages
            messages.warning(request, f"Configuration warnings: {', '.join(errors)}")
        super().save_model(request, obj, form, change)


@admin.register(SSOSession)
class SSOSessionAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'sso_type', 'provider_name', 'ip_address', 'is_active', 'created_at', 'expires_at')
    list_filter = ('sso_type', 'is_active', 'created_at')
    search_fields = ('user__email', 'provider_name', 'ip_address', 'external_session_id')
    readonly_fields = ('created_at', 'last_activity')
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Session Information', {
            'fields': ('user', 'sso_type', 'provider_name', 'external_session_id')
        }),
        ('Client Information', {
            'fields': ('session_key', 'ip_address', 'user_agent')
        }),
        ('Status', {
            'fields': ('is_active', 'created_at', 'last_activity', 'expires_at')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'


  users signals.py:
from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.utils import timezone
from .models import User, Profile, AuditLog, UserSession, PasswordHistory
from .utils import get_client_ip, get_user_agent, create_audit_log, parse_user_agent, get_geolocation_from_ip


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create a profile when a new user is created."""
    if created and instance.is_organizer:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save the profile when the user is saved."""
    if instance.is_organizer and hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log successful user login."""
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    # Update user's last login IP
    user.last_login_ip = ip_address
    user.save(update_fields=['last_login_ip'])
    
    # Create or update session record
    session_key = request.session.session_key
    if session_key:
        # Get geolocation data
        geo_data = get_geolocation_from_ip(ip_address)
        device_info = parse_user_agent(user_agent)
        
        UserSession.objects.update_or_create(
            user=user,
            session_key=session_key,
            defaults={
                'ip_address': ip_address,
                'country': geo_data['country'],
                'city': geo_data['city'],
                'user_agent': user_agent,
                'device_info': device_info,
                'expires_at': timezone.now() + timezone.timedelta(days=30),
                'is_active': True
            }
        )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log user logout."""
    if user:
        # Deactivate session
        session_key = request.session.session_key
        if session_key:
            # Delete Django session
            try:
                from django.contrib.sessions.models import Session
                Session.objects.filter(session_key=session_key).delete()
            except:
                pass
            
            # Deactivate our session record
            UserSession.objects.filter(
                user=user,
                session_key=session_key
            ).update(is_active=False)


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """Log failed login attempts."""
    email = credentials.get('username')  # Django uses 'username' even for email
    if email:
        try:
            user = User.objects.get(email=email)
            create_audit_log(
                user=user,
                action='login_failed',
                description=f"Failed login attempt from {get_client_ip(request)}",
                request=request
            )
        except User.DoesNotExist:
            # Create anonymous audit log for non-existent users
            AuditLog.objects.create(
                action='login_failed',
                description=f"Failed login attempt for non-existent email: {email}",
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )


@receiver(pre_save, sender=User)
def track_password_changes(sender, instance, **kwargs):
    """Track password changes and save to history."""
    if instance.pk:  # Only for existing users
        try:
            old_user = User.objects.get(pk=instance.pk)
            # Check if password has changed
            if old_user.password != instance.password:
                # Save old password to history
                PasswordHistory.objects.create(
                    user=old_user,
                    password_hash=old_user.password
                )
                
                # Update password changed timestamp
                instance.password_changed_at = timezone.now()
                
                # Reset failed login attempts
                instance.failed_login_attempts = 0
                instance.locked_until = None
        except User.DoesNotExist:
            pass


@receiver(post_save, sender=User)
def cleanup_old_password_history(sender, instance, **kwargs):
    """Keep only the last 10 passwords in history."""
    if hasattr(instance, '_password_changed'):
        # Keep only the last 10 passwords
        old_passwords = PasswordHistory.objects.filter(user=instance).order_by('-created_at')[10:]
        if old_passwords:
            PasswordHistory.objects.filter(
                user=instance,
                id__in=[p.id for p in old_passwords]
            ).delete()


@receiver(post_delete, sender=User)
def cleanup_user_data(sender, instance, **kwargs):
    """Clean up user-related data when user is deleted."""
    # This signal will automatically clean up related objects due to CASCADE,
    # but we can add custom cleanup logic here if needed
    
    create_audit_log(
        user=None,  # User is being deleted
        action='user_deleted',
        description=f"User account deleted: {instance.email}",
        metadata={'user_id': str(instance.id), 'email': instance.email}
    )