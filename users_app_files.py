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
