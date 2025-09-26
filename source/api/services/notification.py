"""
Path: infrastructure/source/api/services/notification.py
Version: 1
"""

import logging
import asyncio
import smtplib
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

from .interfaces import NotificationServiceInterface
from ..config import get_settings
from ..database import log_audit_event

logger = logging.getLogger(__name__)
settings = get_settings()


class NotificationService(NotificationServiceInterface):
    """Production notification service for email and alerts"""
    
    def __init__(self, test_hooks=None):
        self.test_hooks = test_hooks
        
        # Email configuration
        self.smtp_server = settings.smtp_server if hasattr(settings, 'smtp_server') else None
        self.smtp_port = getattr(settings, 'smtp_port', 587)
        self.smtp_username = getattr(settings, 'smtp_username', None)
        self.smtp_password = getattr(settings, 'smtp_password', None)
        self.smtp_use_tls = getattr(settings, 'smtp_use_tls', True)
        self.from_email = getattr(settings, 'from_email', 'noreply@opendocseal.com')
        self.from_name = getattr(settings, 'from_name', 'OpenDocSeal')
        
        # Notification templates
        self.templates = {
            'email_verification': {
                'subject': 'Vérifiez votre email - OpenDocSeal',
                'template': 'email_verification.html'
            },
            'password_reset': {
                'subject': 'Réinitialisation de mot de passe - OpenDocSeal',
                'template': 'password_reset.html'
            },
            'document_ready': {
                'subject': 'Document traité - OpenDocSeal',
                'template': 'document_ready.html'
            },
            'security_alert': {
                'subject': 'Alerte de sécurité - OpenDocSeal',
                'template': 'security_alert.html'
            }
        }
        
        # Statistics
        self._stats = {
            'emails_sent': 0,
            'emails_failed': 0,
            'alerts_sent': 0
        }
    
    async def send_email_verification(self, user_id: str, email: str) -> bool:
        """Send email verification notification"""
        try:
            # Generate verification token (simplified for example)
            verification_token = f"verify_{user_id}_{datetime.now().timestamp()}"
            verification_url = f"{settings.frontend_url}/verify-email?token={verification_token}"
            
            html_content = f"""
            <html>
                <body>
                    <h2>Vérifiez votre adresse email</h2>
                    <p>Bonjour,</p>
                    <p>Merci de vous être inscrit sur OpenDocSeal. Pour activer votre compte, veuillez cliquer sur le lien ci-dessous :</p>
                    <p><a href="{verification_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Vérifier mon email</a></p>
                    <p>Si vous n'avez pas demandé cette inscription, vous pouvez ignorer cet email.</p>
                    <p>Cordialement,<br>L'équipe OpenDocSeal</p>
                </body>
            </html>
            """
            
            success = await self._send_email(
                to_email=email,
                subject=self.templates['email_verification']['subject'],
                html_content=html_content
            )
            
            if success:
                # Log audit event
                await log_audit_event(
                    action="email_verification_sent",
                    user_id=user_id,
                    details={"email": email, "verification_token": verification_token[:20] + "..."}
                )
                
                self._stats['emails_sent'] += 1
                logger.info(f"Email verification sent to: {email}")
            else:
                self._stats['emails_failed'] += 1
                logger.error(f"Failed to send email verification to: {email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Email verification error: {e}")
            self._stats['emails_failed'] += 1
            return False
    
    async def send_password_reset(self, user_id: str, email: str, reset_token: str) -> bool:
        """Send password reset email"""
        try:
            reset_url = f"{settings.frontend_url}/reset-password?token={reset_token}"
            
            html_content = f"""
            <html>
                <body>
                    <h2>Réinitialisation de mot de passe</h2>
                    <p>Bonjour,</p>
                    <p>Vous avez demandé la réinitialisation de votre mot de passe OpenDocSeal.</p>
                    <p>Cliquez sur le lien ci-dessous pour créer un nouveau mot de passe :</p>
                    <p><a href="{reset_url}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Réinitialiser mon mot de passe</a></p>
                    <p><strong>Ce lien expire dans 1 heure pour votre sécurité.</strong></p>
                    <p>Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email et contacter notre support.</p>
                    <p>Cordialement,<br>L'équipe OpenDocSeal</p>
                </body>
            </html>
            """
            
            success = await self._send_email(
                to_email=email,
                subject=self.templates['password_reset']['subject'],
                html_content=html_content
            )
            
            if success:
                await log_audit_event(
                    action="password_reset_email_sent",
                    user_id=user_id,
                    details={"email": email}
                )
                
                self._stats['emails_sent'] += 1
                logger.info(f"Password reset email sent to: {email}")
            else:
                self._stats['emails_failed'] += 1
                logger.error(f"Failed to send password reset email to: {email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Password reset email error: {e}")
            self._stats['emails_failed'] += 1
            return False
    
    async def send_document_notification(
        self, user_id: str, document_id: str, event_type: str
    ) -> bool:
        """Send document event notification"""
        try:
            # Get user email (simplified - would normally query user service)
            user_email = f"user_{user_id}@example.com"  # Placeholder
            
            if event_type == "processing_complete":
                subject = "Document traité avec succès"
                html_content = f"""
                <html>
                    <body>
                        <h2>Document traité</h2>
                        <p>Bonjour,</p>
                        <p>Votre document (ID: {document_id}) a été traité avec succès et est maintenant disponible avec sa preuve d'intégrité blockchain.</p>
                        <p><a href="{settings.frontend_url}/documents/{document_id}">Voir le document</a></p>
                        <p>Cordialement,<br>L'équipe OpenDocSeal</p>
                    </body>
                </html>
                """
            elif event_type == "blockchain_confirmed":
                subject = "Confirmation blockchain reçue"
                html_content = f"""
                <html>
                    <body>
                        <h2>Confirmation blockchain</h2>
                        <p>Bonjour,</p>
                        <p>La preuve blockchain de votre document (ID: {document_id}) a été confirmée sur la blockchain.</p>
                        <p>Votre document bénéficie maintenant d'une preuve d'intégrité cryptographique inaltérable.</p>
                        <p><a href="{settings.frontend_url}/documents/{document_id}">Voir la preuve</a></p>
                        <p>Cordialement,<br>L'équipe OpenDocSeal</p>
                    </body>
                </html>
                """
            else:
                logger.warning(f"Unknown document event type: {event_type}")
                return False
            
            success = await self._send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                await log_audit_event(
                    action="document_notification_sent",
                    user_id=user_id,
                    details={"document_id": document_id, "event_type": event_type}
                )
                
                self._stats['emails_sent'] += 1
            else:
                self._stats['emails_failed'] += 1
            
            return success
            
        except Exception as e:
            logger.error(f"Document notification error: {e}")
            self._stats['emails_failed'] += 1
            return False
    
    async def send_security_alert(self, user_id: str, alert_type: str, details: Dict[str, Any]) -> bool:
        """Send security alert"""
        try:
            # Get user email (simplified)
            user_email = f"user_{user_id}@example.com"  # Placeholder
            
            alert_messages = {
                'suspicious_login': 'Tentative de connexion suspecte détectée',
                'password_changed': 'Votre mot de passe a été modifié',
                'api_key_created': 'Nouvelle clé API créée',
                'multiple_failed_logins': 'Plusieurs tentatives de connexion échouées'
            }
            
            alert_message = alert_messages.get(alert_type, f'Alerte de sécurité: {alert_type}')
            
            html_content = f"""
            <html>
                <body>
                    <h2 style="color: #dc3545;">Alerte de sécurité</h2>
                    <p>Bonjour,</p>
                    <p><strong>{alert_message}</strong></p>
                    <p>Détails de l'événement :</p>
                    <ul>
            """
            
            for key, value in details.items():
                html_content += f"<li><strong>{key}:</strong> {value}</li>"
            
            html_content += f"""
                    </ul>
                    <p>Si cette action n'a pas été effectuée par vous, veuillez immédiatement :</p>
                    <ol>
                        <li>Changer votre mot de passe</li>
                        <li>Vérifier vos clés API</li>
                        <li>Contacter notre support</li>
                    </ol>
                    <p>Cordialement,<br>L'équipe sécurité OpenDocSeal</p>
                </body>
            </html>
            """
            
            success = await self._send_email(
                to_email=user_email,
                subject=self.templates['security_alert']['subject'],
                html_content=html_content,
                priority='high'
            )
            
            if success:
                await log_audit_event(
                    action="security_alert_sent",
                    user_id=user_id,
                    details={"alert_type": alert_type, "details": details}
                )
                
                self._stats['alerts_sent'] += 1
                logger.warning(f"Security alert sent to user {user_id}: {alert_type}")
            
            return success
            
        except Exception as e:
            logger.error(f"Security alert error: {e}")
            return False
    
    async def _send_email(
        self, 
        to_email: str, 
        subject: str, 
        html_content: str, 
        priority: str = 'normal'
    ) -> bool:
        """Internal method to send email via SMTP"""
        try:
            # Skip if SMTP not configured
            if not self.smtp_server:
                logger.warning("SMTP not configured, skipping email send")
                return False
            
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = formataddr((self.from_name, self.from_email))
            message['To'] = to_email
            
            # Add priority header if high
            if priority == 'high':
                message['X-Priority'] = '1'
                message['X-MSMail-Priority'] = 'High'
            
            # Attach HTML content
            html_part = MIMEText(html_content, 'html', 'utf-8')
            message.attach(html_part)
            
            # Send email in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None, 
                self._send_smtp_email, 
                message, 
                to_email
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Email sending error: {e}")
            return False
    
    def _send_smtp_email(self, message: MIMEMultipart, to_email: str) -> bool:
        """Send email via SMTP (blocking operation for thread pool)"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                
                server.send_message(message, to_addrs=[to_email])
                
            return True
            
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get notification service statistics"""
        return {
            "emails_sent": self._stats['emails_sent'],
            "emails_failed": self._stats['emails_failed'],
            "alerts_sent": self._stats['alerts_sent'],
            "success_rate": round(
                self._stats['emails_sent'] / max(
                    self._stats['emails_sent'] + self._stats['emails_failed'], 1
                ) * 100, 2
            ),
            "smtp_configured": bool(self.smtp_server)
        }