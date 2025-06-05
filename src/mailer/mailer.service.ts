import { Injectable, Logger } from '@nestjs/common';

import { MailerService as NestMailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  constructor(private readonly mailer: NestMailerService) {}

  async sendRegistrationOtp(email: string, otp: string): Promise<void> {
    try {
      await this.mailer.sendMail({
        context: {
          email,
          otp
        },
        subject: 'Registration OTP',
        template: './registration-otp',
        text: `Your OTP for account verification is: ${otp}`,
        to: email
      });

      this.logger.log(`Registration OTP sent successfully to: ${email}`);
    } catch (error) {
      this.logger.error('Error sending OTP email.', error.stack);
    }
  }

  async sendLoginOtp(email: string, otp: string): Promise<void> {
    try {
      await this.mailer.sendMail({
        context: {
          email,
          otp
        },
        subject: 'Login OTP',
        template: './login-otp',
        text: `Your OTP for password reset is: ${otp}`,
        to: email
      });

      this.logger.log(`Login OTP sent successfully to: ${email}`);
    } catch (error) {
      this.logger.error('Error sending OTP email:', error.stack);
    }
  }

  async notifySuccessfulRegistration(email: string, otp: string) {
    try {
      // Send email with OTP for account verification
      await this.mailer.sendMail({
        html: /* HTML */ `<p>Dear user,</p>
          <p
            >Thank you for registering with us. To complete your account
            registration, please use the following One-Time Password (OTP):</p
          >
          <p><strong>OTP: ${otp}</strong></p>
          <p
            >This OTP is valid for 15 minutes. If you did not request this
            registration, please disregard this email.</p
          >
          <p
            >If you have any issues or concerns, please contact our support
            team.</p
          >
          <p>Thank you.</p>`,
        subject: 'Account Registration - OTP Verification',
        text: `Dear user,
          Thank you for registering with us. To complete your account registration, please use the following One-Time Password (OTP):
          OTP: ${otp}
          This OTP is valid for 15 minutes. If you did not request this registration, please disregard this email.
          If you have any issues or concerns, please contact our support team.
          Thank you.`,
        to: email // Send to the provided email
      });

      this.logger.log(`Successfully registration email sent to: ${email}`);
    } catch (error) {
      console.error('Error sending registration OTP email:', error);
    }
  }

  async notifyPasswordChanged(email: string) {
    try {
      // Send email notifying users about password change
      await this.mailer.sendMail({
        html: /* HTML */ `<p>Dear user,</p>
          <p
            >We wanted to inform you that your password has been successfully
            changed. If you did not initiate this change, please
            <a href="#">reset your password</a> immediately to secure your
            account.</p
          >
          <p
            >If you have any concerns or need further assistance, please contact
            our support team.</p
          >
          <p>Thank you.</p>`,
        subject: 'Password Change Notification',
        text: `Dear user,
          We wanted to inform you that your password has been successfully changed. If you did not initiate this change, please reset your password immediately to secure your account.
          If you have any concerns or need further assistance, please contact our support team.
          Thank you.`,
        to: email // Send to the provided email
      });

      this.logger.log(`Successfully password change email sent to: ${email}`);
    } catch (error) {
      console.error('Error sending password change notification email:', error);
    }
  }

  async sendPasswordResetRequest(email: string, otp: string) {
    try {
      // Send email notifying users about password reset request
      await this.mailer.sendMail({
        html: /* HTML */ `<p>Dear user,</p>
          <p
            >We received a request to reset your password. If you did not make
            this request, please ignore this email.</p
          >
          <p>OTP-code <strong>${otp}</strong></p>
          <p
            >If you have any issues or concerns, please contact our support
            team.</p
          >
          <p>Thank you.</p>`,
        subject: 'Password Reset Request',
        text: `Dear user,
          We received a request to reset your password. If you did not make this request, please ignore this email. 
          To reset your password, please provide the OTP
          If you have any issues or concerns, please contact our support team.
          Thank you.`,
        to: email // Send to the provided email
      });

      this.logger.log(`Password reset request email sent to: ${email}`);
    } catch (error) {
      console.error('Error sending password reset request email:', error);
    }
  }

  async notifySuccessfulLogin(email: string) {
    try {
      // Send email notifying users about successful login
      await this.mailer.sendMail({
        html: /* HTML */ `<p>Dear user,</p>
          <p
            >We wanted to let you know that your account has been successfully
            logged into. If this was not you, please take immediate action to
            secure your account by <a href="#">resetting your password</a>.</p
          >
          <p>Thank you.</p>`,
        subject: 'Successful Login Notification',
        text: `Dear user,
          We wanted to let you know that your account has been successfully logged into. 
          If this was not you, please take immediate action to secure your account by resetting your password.
          Thank you.`,
        to: email
      });

      this.logger.log(`Successfully login email sent to: ${email}`);
    } catch (error) {
      console.error('Error sending login notification email:', error);
    }
  }
}
