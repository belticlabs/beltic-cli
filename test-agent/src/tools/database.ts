import pg from 'pg';
import { config } from '../config.js';

const { Pool } = pg;

interface DatabaseQueryInput {
  query: string;
  table?: string;
  filters?: Record<string, any>;
  limit?: number;
}

// Connection pool (lazy initialization)
let pool: pg.Pool | null = null;

function getPool(): pg.Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: config.databaseUrl,
      max: config.databaseMaxConnections,
    });
  }
  return pool;
}

export const DatabaseTool = {
  name: 'query_database',
  description: 'Query the support ticket database for customer information, ticket history, or statistics. Read-only access.',
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description: 'Natural language description of what to query',
      },
      table: {
        type: 'string',
        enum: ['tickets', 'customers', 'interactions'],
        description: 'Database table to query',
      },
      filters: {
        type: 'object',
        description: 'Key-value filters to apply',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of results to return',
        default: 10,
      },
    },
    required: ['query', 'table'],
  },

  async execute(input: DatabaseQueryInput) {
    console.log('[DATABASE] Processing query...');

    const { table, filters, limit = 10 } = input;

    // Security: Validate table name (whitelist)
    const allowedTables = ['tickets', 'customers', 'interactions'];
    if (!allowedTables.includes(table || '')) {
      return {
        success: false,
        error: 'Invalid table name',
      };
    }

    // In production, this would execute real queries
    // For testing, we'll return mock data
    if (process.env.NODE_ENV === 'production') {
      try {
        const dbPool = getPool();

        // Build safe query with parameterized values
        let query = `SELECT * FROM ${table}`;
        const values: any[] = [];
        let paramCount = 1;

        if (filters && Object.keys(filters).length > 0) {
          const whereClauses = Object.entries(filters).map(([key, value]) => {
            values.push(value);
            return `${key} = $${paramCount++}`;
          });
          query += ` WHERE ${whereClauses.join(' AND ')}`;
        }

        query += ` LIMIT $${paramCount}`;
        values.push(limit);

        const result = await dbPool.query(query, values);

        return {
          success: true,
          rowCount: result.rowCount,
          rows: result.rows,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    }

    // Simulation mode - return mock data
    console.log('[DATABASE] SIMULATION MODE - Returning mock data');
    console.log(`[DATABASE] Table: ${table}`);
    console.log(`[DATABASE] Filters:`, filters);
    console.log(`[DATABASE] Limit: ${limit}`);

    const mockData = generateMockData(table, filters, limit);

    return {
      success: true,
      rowCount: mockData.length,
      rows: mockData,
      simulated: true,
    };
  },
};

function generateMockData(table?: string, filters?: Record<string, any>, limit: number = 10): any[] {
  switch (table) {
    case 'tickets':
      return [
        {
          id: 12345,
          customer_email: 'john@example.com',
          subject: 'Login issues',
          status: 'open',
          priority: 'high',
          created_at: '2024-01-15T10:30:00Z',
          updated_at: '2024-01-15T14:20:00Z',
        },
        {
          id: 12346,
          customer_email: 'jane@example.com',
          subject: 'Billing question',
          status: 'resolved',
          priority: 'medium',
          created_at: '2024-01-14T09:15:00Z',
          updated_at: '2024-01-14T16:45:00Z',
        },
      ].slice(0, limit);

    case 'customers':
      return [
        {
          id: 1001,
          email: 'john@example.com',
          name: 'John Doe',
          plan: 'premium',
          created_at: '2023-06-01T00:00:00Z',
          total_tickets: 5,
        },
        {
          id: 1002,
          email: 'jane@example.com',
          name: 'Jane Smith',
          plan: 'basic',
          created_at: '2023-08-15T00:00:00Z',
          total_tickets: 2,
        },
      ].slice(0, limit);

    case 'interactions':
      return [
        {
          id: 5001,
          ticket_id: 12345,
          type: 'email',
          direction: 'inbound',
          content: 'I cannot log in to my account',
          timestamp: '2024-01-15T10:30:00Z',
        },
        {
          id: 5002,
          ticket_id: 12345,
          type: 'email',
          direction: 'outbound',
          content: 'Thank you for contacting support...',
          timestamp: '2024-01-15T11:00:00Z',
        },
      ].slice(0, limit);

    default:
      return [];
  }
}
