import nodemailer from 'nodemailer';
import { config } from '../config.js';

interface EmailInput {
  to: string;
  subject: string;
  body: string;
  cc?: string[];
  priority?: 'high' | 'normal' | 'low';
}

export const EmailTool = {
  name: 'send_email',
  description: 'Send an email to a customer or team member. Requires human approval for sensitive communications.',
  inputSchema: {
    type: 'object',
    properties: {
      to: {
        type: 'string',
        description: 'Email address of the recipient',
      },
      subject: {
        type: 'string',
        description: 'Subject line of the email',
      },
      body: {
        type: 'string',
        description: 'Email body content (plain text or HTML)',
      },
      cc: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional CC recipients',
      },
      priority: {
        type: 'string',
        enum: ['high', 'normal', 'low'],
        description: 'Email priority level',
      },
    },
    required: ['to', 'subject', 'body'],
  },

  async execute(input: EmailInput) {
    console.log('[EMAIL] Preparing to send email...');

    // Validate email address format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(input.to)) {
      return {
        success: false,
        error: 'Invalid email address format',
      };
    }

    // In production, this would actually send the email
    // For testing, we'll just simulate it
    if (process.env.NODE_ENV === 'production' && config.emailUser) {
      const transporter = nodemailer.createTransport({
        host: config.emailHost,
        port: config.emailPort,
        secure: false,
        auth: {
          user: config.emailUser,
          pass: config.emailPassword,
        },
      });

      try {
        const info = await transporter.sendMail({
          from: config.emailFrom,
          to: input.to,
          cc: input.cc?.join(', '),
          subject: input.subject,
          text: input.body,
          priority: input.priority || 'normal',
        });

        return {
          success: true,
          messageId: info.messageId,
          recipients: [input.to, ...(input.cc || [])],
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    }

    // Simulation mode
    console.log('[EMAIL] SIMULATION MODE - Email not actually sent');
    console.log(`[EMAIL] To: ${input.to}`);
    console.log(`[EMAIL] Subject: ${input.subject}`);
    console.log(`[EMAIL] Body: ${input.body.substring(0, 100)}...`);

    return {
      success: true,
      messageId: `<simulated-${Date.now()}@example.com>`,
      recipients: [input.to, ...(input.cc || [])],
      simulated: true,
    };
  },
};
