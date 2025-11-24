# Customer Support Agent

An AI-powered customer support agent built with Claude and equipped with email, database, ticketing, and search capabilities.

## Overview

This agent demonstrates a realistic customer support automation system that can:
- Send emails to customers
- Query the support ticket database
- Create new support tickets
- Search documentation and knowledge bases

## Features

### Tools

1. **Email Tool** (`send_email`)
   - Send emails to customers or team members
   - Support for CC, priority levels
   - Requires human approval for sensitive communications
   - Risk Level: Medium

2. **Database Tool** (`query_database`)
   - Read-only access to support database
   - Query tickets, customers, and interactions
   - Parameterized queries for security
   - Risk Level: Low

3. **Ticket Tool** (`create_ticket`)
   - Create new support tickets
   - Set priority, category, and tags
   - Track in ticketing system
   - Risk Level: Medium

4. **Search Tool** (`web_search`)
   - Search documentation and knowledge base
   - Help answer customer questions
   - Multiple search categories
   - Risk Level: Low

## Setup

### Prerequisites

- Node.js 18+ and npm
- TypeScript
- Anthropic API key

### Installation

```bash
# Install dependencies
npm install

# Build the project
npm run build
```

### Configuration

Create a `.env` file in the root directory:

```env
# Required
ANTHROPIC_API_KEY=your_api_key_here

# Optional - AI Configuration
MODEL=claude-3-5-sonnet-20241022
MAX_TOKENS=4096

# Optional - Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@example.com
EMAIL_PASSWORD=your_app_password
EMAIL_FROM=support@example.com

# Optional - Database Configuration
DATABASE_URL=postgresql://localhost:5432/support
DATABASE_MAX_CONNECTIONS=10

# Optional - Ticket System
TICKET_SYSTEM_URL=https://tickets.example.com
TICKET_API_KEY=your_ticket_api_key

# Optional - Search
SEARCH_API_KEY=your_search_api_key

# Environment
NODE_ENV=development
```

## Usage

### Development Mode

```bash
# Run with tsx (no build required)
npm run dev
```

### Production Mode

```bash
# Build and run
npm run build
npm start
```

### Example Interactions

The agent can handle requests like:

```
User: "I need to send a follow-up email to john@example.com about their recent support ticket #12345"

User: "Can you check the database for all tickets from yesterday?"

User: "Create a new ticket for a customer reporting login issues"

User: "Search the knowledge base for information about password resets"
```

## Architecture

```
src/
├── index.ts          # Main agent loop with Claude integration
├── config.ts         # Configuration management
└── tools/
    ├── email.ts      # Email sending tool
    ├── database.ts   # Database query tool
    ├── ticket.ts     # Ticket creation tool
    └── search.ts     # Search tool
```

## Beltic Integration

This agent is designed to work with the Beltic credential system:

### Generate Agent Fingerprint

```bash
# From the test-agent directory
../target/release/beltic fingerprint
```

### Create Agent Manifest

```bash
# Initialize Beltic configuration
../target/release/beltic init

# This will create a .beltic.yaml file with agent metadata
```

### Verify Configuration

The agent includes all information needed for a complete Beltic agent credential:

- **Agent Identity**: Name, version, description
- **Tools**: 4 tools with clear risk categorization
- **Data Handling**: Email addresses, support tickets, customer data
- **Human Oversight**: Configured for sensitive operations
- **Deployment**: Standalone TypeScript application

## Testing

Run tests:

```bash
npm test
```

## Security Considerations

1. **Email Tool**: Requires validation of email addresses, supports human approval workflow
2. **Database Tool**: Read-only access, parameterized queries to prevent SQL injection
3. **Ticket Tool**: Input validation for all fields
4. **Search Tool**: Rate limiting and query validation

## Development Notes

- The agent runs in simulation mode by default (no actual emails sent, mock database data)
- Set `NODE_ENV=production` and provide real credentials for production use
- All tools include comprehensive error handling and logging
- The conversation history is maintained for context across multiple turns

## License

MIT
