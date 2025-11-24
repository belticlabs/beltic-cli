import { config } from '../config.js';

interface CreateTicketInput {
  customerEmail: string;
  subject: string;
  description: string;
  priority?: 'low' | 'medium' | 'high' | 'urgent';
  category?: string;
  tags?: string[];
}

export const TicketTool = {
  name: 'create_ticket',
  description: 'Create a new support ticket in the ticketing system. Use this when a customer issue needs to be tracked.',
  inputSchema: {
    type: 'object',
    properties: {
      customerEmail: {
        type: 'string',
        description: 'Email address of the customer',
      },
      subject: {
        type: 'string',
        description: 'Brief summary of the issue',
      },
      description: {
        type: 'string',
        description: 'Detailed description of the issue',
      },
      priority: {
        type: 'string',
        enum: ['low', 'medium', 'high', 'urgent'],
        description: 'Priority level of the ticket',
        default: 'medium',
      },
      category: {
        type: 'string',
        description: 'Ticket category (e.g., billing, technical, account)',
      },
      tags: {
        type: 'array',
        items: { type: 'string' },
        description: 'Tags to help categorize the ticket',
      },
    },
    required: ['customerEmail', 'subject', 'description'],
  },

  async execute(input: CreateTicketInput) {
    console.log('[TICKET] Creating new support ticket...');

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(input.customerEmail)) {
      return {
        success: false,
        error: 'Invalid customer email format',
      };
    }

    // Validate subject length
    if (input.subject.length < 5) {
      return {
        success: false,
        error: 'Subject must be at least 5 characters long',
      };
    }

    // In production, this would call the actual ticket system API
    if (process.env.NODE_ENV === 'production' && config.ticketApiKey) {
      try {
        const response = await fetch(`${config.ticketSystemUrl}/api/tickets`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${config.ticketApiKey}`,
          },
          body: JSON.stringify({
            customer_email: input.customerEmail,
            subject: input.subject,
            description: input.description,
            priority: input.priority || 'medium',
            category: input.category,
            tags: input.tags || [],
            source: 'ai_agent',
            created_by: config.agentName,
          }),
        });

        if (!response.ok) {
          throw new Error(`API error: ${response.statusText}`);
        }

        const data = await response.json();

        return {
          success: true,
          ticketId: data.id,
          ticketUrl: data.url,
          status: data.status,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    }

    // Simulation mode
    console.log('[TICKET] SIMULATION MODE - Ticket not actually created');
    console.log(`[TICKET] Customer: ${input.customerEmail}`);
    console.log(`[TICKET] Subject: ${input.subject}`);
    console.log(`[TICKET] Priority: ${input.priority || 'medium'}`);

    const ticketId = Math.floor(Math.random() * 90000) + 10000;

    return {
      success: true,
      ticketId: ticketId,
      ticketUrl: `${config.ticketSystemUrl}/tickets/${ticketId}`,
      status: 'open',
      simulated: true,
    };
  },
};
