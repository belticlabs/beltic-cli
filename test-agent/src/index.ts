import Anthropic from '@anthropic-ai/sdk';
import { config } from './config.js';
import { EmailTool } from './tools/email.js';
import { DatabaseTool } from './tools/database.js';
import { TicketTool } from './tools/ticket.js';
import { WebSearchTool } from './tools/search.js';

interface Tool {
  name: string;
  description: string;
  inputSchema: any;
  execute: (input: any) => Promise<any>;
}

class CustomerSupportAgent {
  private client: Anthropic;
  private tools: Map<string, Tool>;
  private conversationHistory: Array<any> = [];

  constructor() {
    this.client = new Anthropic({
      apiKey: config.anthropicApiKey,
    });

    this.tools = new Map([
      ['send_email', EmailTool],
      ['query_database', DatabaseTool],
      ['create_ticket', TicketTool],
      ['web_search', WebSearchTool],
    ]);
  }

  async processMessage(userMessage: string): Promise<string> {
    console.log(`\nUser: ${userMessage}`);

    // Add user message to history
    this.conversationHistory.push({
      role: 'user',
      content: userMessage,
    });

    let response;
    let toolCalls = 0;
    const maxToolCalls = 5;

    while (toolCalls < maxToolCalls) {
      // Call Claude with tool definitions
      response = await this.client.messages.create({
        model: config.model,
        max_tokens: config.maxTokens,
        messages: this.conversationHistory,
        tools: this.getToolDefinitions(),
      });

      // Check if Claude wants to use a tool
      const toolUseBlock = response.content.find(
        (block: any) => block.type === 'tool_use'
      );

      if (!toolUseBlock) {
        // No tool use, return the text response
        const textBlock = response.content.find(
          (block: any) => block.type === 'text'
        );
        const assistantMessage = textBlock?.text || 'No response generated.';

        this.conversationHistory.push({
          role: 'assistant',
          content: response.content,
        });

        console.log(`\nAssistant: ${assistantMessage}`);
        return assistantMessage;
      }

      // Execute the tool
      console.log(`\nExecuting tool: ${toolUseBlock.name}`);
      const tool = this.tools.get(toolUseBlock.name);

      if (!tool) {
        throw new Error(`Unknown tool: ${toolUseBlock.name}`);
      }

      let toolResult;
      try {
        toolResult = await tool.execute(toolUseBlock.input);
        console.log(`Tool result:`, toolResult);
      } catch (error: any) {
        toolResult = { error: error.message };
        console.error(`Tool error:`, error.message);
      }

      // Add assistant's tool use and tool result to history
      this.conversationHistory.push({
        role: 'assistant',
        content: response.content,
      });

      this.conversationHistory.push({
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: toolUseBlock.id,
            content: JSON.stringify(toolResult),
          },
        ],
      });

      toolCalls++;
    }

    throw new Error('Max tool calls exceeded');
  }

  private getToolDefinitions() {
    return Array.from(this.tools.values()).map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.inputSchema,
    }));
  }

  clearHistory() {
    this.conversationHistory = [];
  }
}

// Main execution
async function main() {
  console.log('Customer Support Agent starting...\n');
  console.log('Configuration:', {
    model: config.model,
    maxTokens: config.maxTokens,
  });

  const agent = new CustomerSupportAgent();

  // Example conversation
  try {
    await agent.processMessage(
      'I need to send a follow-up email to john@example.com about their recent support ticket #12345'
    );

    await agent.processMessage(
      'Can you check the database for all tickets from yesterday?'
    );

    await agent.processMessage(
      'Create a new ticket for a customer reporting login issues'
    );
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }

  console.log('\n\nAgent execution completed successfully!');
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { CustomerSupportAgent };
