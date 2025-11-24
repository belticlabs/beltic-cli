import { config as loadEnv } from 'dotenv';

loadEnv();

export const config = {
  // AI Model Configuration
  anthropicApiKey: process.env.ANTHROPIC_API_KEY || '',
  model: process.env.MODEL || 'claude-3-5-sonnet-20241022',
  maxTokens: parseInt(process.env.MAX_TOKENS || '4096'),

  // Email Configuration
  emailHost: process.env.EMAIL_HOST || 'smtp.gmail.com',
  emailPort: parseInt(process.env.EMAIL_PORT || '587'),
  emailUser: process.env.EMAIL_USER || '',
  emailPassword: process.env.EMAIL_PASSWORD || '',
  emailFrom: process.env.EMAIL_FROM || 'support@example.com',

  // Database Configuration
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/support',
  databaseMaxConnections: parseInt(process.env.DATABASE_MAX_CONNECTIONS || '10'),

  // Ticket System Configuration
  ticketSystemUrl: process.env.TICKET_SYSTEM_URL || 'https://tickets.example.com',
  ticketApiKey: process.env.TICKET_API_KEY || '',

  // Search Configuration
  searchApiKey: process.env.SEARCH_API_KEY || '',

  // Agent Configuration
  agentName: 'Customer Support Agent',
  agentVersion: '1.0.0',
  humanOversightEnabled: true,
  maxToolRetries: 3,
};

export type Config = typeof config;
