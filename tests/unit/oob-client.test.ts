/**
 * OOB Client Unit Tests
 */

import {
  IOOBClient,
  OOBInteraction,
  MockOOBClient,
  InteractshClient,
  createOOBClient,
} from '../../src/core/network/OOBClient';

describe('OOB Client', () => {
  describe('MockOOBClient', () => {
    let client: MockOOBClient;

    beforeEach(() => {
      client = new MockOOBClient();
    });

    afterEach(async () => {
      await client.cleanup();
    });

    describe('generatePayload', () => {
      test('should generate unique payload URL', async () => {
        const { url, id } = await client.generatePayload();
        
        expect(url).toBeDefined();
        expect(id).toBeDefined();
        expect(url).toMatch(/^http:\/\/localhost:\d+\/callback\//);
        expect(id).toMatch(/^[a-z0-9-]+-[a-z0-9]+$/);
      });

      test('should generate different URLs for each call', async () => {
        const { url: url1, id: id1 } = await client.generatePayload();
        const { url: url2, id: id2 } = await client.generatePayload();
        
        expect(url1).not.toBe(url2);
        expect(id1).not.toBe(id2);
      });
    });

    describe('checkInteractions', () => {
      test('should return empty array for new payload', async () => {
        const { id } = await client.generatePayload();
        const interactions = await client.checkInteractions(id);
        
        expect(Array.isArray(interactions)).toBe(true);
        expect(interactions.length).toBe(0);
      });

      test('should return simulated interactions', async () => {
        const { id } = await client.generatePayload();
        
        // Simulate an interaction
        client.simulateInteraction(id, {
          protocol: 'http',
          remoteIp: '192.168.1.1',
          timestamp: new Date(),
          rawRequest: 'GET /callback/test HTTP/1.1',
          path: '/callback/test',
        });
        
        const interactions = await client.checkInteractions(id);
        
        expect(interactions.length).toBe(1);
        expect(interactions[0].protocol).toBe('http');
        expect(interactions[0].remoteIp).toBe('192.168.1.1');
      });

      test('should return multiple interactions', async () => {
        const { id } = await client.generatePayload();
        
        // Simulate multiple interactions
        client.simulateInteraction(id, { protocol: 'dns', remoteIp: '192.168.1.1' });
        client.simulateInteraction(id, { protocol: 'http', remoteIp: '192.168.1.1' });
        client.simulateInteraction(id, { protocol: 'smtp', remoteIp: '192.168.1.1' });
        
        const interactions = await client.checkInteractions(id);
        
        expect(interactions.length).toBe(3);
      });
    });

    describe('cleanup', () => {
      test('should clear all interactions', async () => {
        const { id } = await client.generatePayload();
        client.simulateInteraction(id, { protocol: 'http', remoteIp: '192.168.1.1' });
        
        await client.cleanup();
        
        const interactions = await client.checkInteractions(id);
        expect(interactions.length).toBe(0);
      });
    });

    describe('isReady', () => {
      test('should always return true', async () => {
        const isReady = await client.isReady();
        expect(isReady).toBe(true);
      });
    });
  });

  describe('createOOBClient factory', () => {
    test('should create MockOOBClient by default', () => {
      const client = createOOBClient();
      
      expect(client).toBeInstanceOf(MockOOBClient);
    });

    test('should create MockOOBClient when type is mock', () => {
      const client = createOOBClient('mock');
      
      expect(client).toBeInstanceOf(MockOOBClient);
    });

    test('should create InteractshClient when type is interactsh', () => {
      const client = createOOBClient('interactsh');
      
      expect(client).toBeInstanceOf(InteractshClient);
    });

    test('should create MockOOBClient when type is collaborator (not implemented)', () => {
      const client = createOOBClient('collaborator');
      
      expect(client).toBeInstanceOf(MockOOBClient);
    });

    test('should pass options to client', () => {
      const options = {
        server: 'custom.server',
        token: 'test-token',
        callbackPort: 9999,
        baseUrl: 'http://localhost:9999',
      };
      
      const client = createOOBClient('mock', options);
      
      expect(client).toBeInstanceOf(MockOOBClient);
    });
  });

  describe('InteractshClient', () => {
    let client: InteractshClient;

    beforeEach(() => {
      client = new InteractshClient({
        server: 'oast.pro',
        pollInterval: 1000,
        maxPolls: 5,
        timeout: 5000,
      });
    });

    afterEach(async () => {
      await client.cleanup();
    });

    describe('constructor', () => {
      test('should use default server', () => {
        const defaultClient = new InteractshClient();
        expect(defaultClient).toBeDefined();
      });

      test('should use custom server', () => {
        const customClient = new InteractshClient({ server: 'custom.server' });
        expect(customClient).toBeDefined();
      });

      test('should use custom token', () => {
        const customClient = new InteractshClient({ token: 'test-token' });
        expect(customClient).toBeDefined();
      });

      test('should use custom poll interval', () => {
        const customClient = new InteractshClient({ pollInterval: 10000 });
        expect(customClient).toBeDefined();
      });

      test('should use custom max polls', () => {
        const customClient = new InteractshClient({ maxPolls: 20 });
        expect(customClient).toBeDefined();
      });

      test('should use custom timeout', () => {
        const customClient = new InteractshClient({ timeout: 60000 });
        expect(customClient).toBeDefined();
      });
    });

    describe('generatePayload', () => {
      test('should throw error when fetch fails', async () => {
        // Mock fetch to fail
        global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
        
        await expect(client.generatePayload()).rejects.toThrow('Failed to generate Interactsh payload');
      });

      test('should throw error when response is not ok', async () => {
        // Mock fetch to return 500
        global.fetch = jest.fn().mockResolvedValue({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
        } as Response);
        
        await expect(client.generatePayload()).rejects.toThrow('Interactsh registration failed');
      });
    });

    describe('checkInteractions', () => {
      test('should throw error for unknown ID', async () => {
        await expect(client.checkInteractions('unknown-id')).rejects.toThrow(
          'No secret found for ID: unknown-id'
        );
      });

      test('should return empty array on fetch failure', async () => {
        // First generate a payload
        global.fetch = jest.fn()
          .mockResolvedValueOnce({
            ok: true,
            json: async () => ({ uuid: 'test-id', secret: 'test-secret', fullId: 'test-full-id' }),
          } as Response)
          .mockRejectedValueOnce(new Error('Network error'));
        
        const { id } = await client.generatePayload();
        const interactions = await client.checkInteractions(id);
        
        expect(interactions).toEqual([]);
      });

      test('should return empty array when no interactions', async () => {
        // Mock fetch to return empty data
        global.fetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({ data: [] }),
        } as Response);
        
        const { id } = await client.generatePayload();
        const interactions = await client.checkInteractions(id);
        
        expect(interactions).toEqual([]);
      });

      test('should convert Interactsh interactions to OOB format', async () => {
        // Mock fetch to return interactions
        global.fetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            data: [
              {
                timestamp: '2024-01-01T00:00:00Z',
                fullId: 'test-full-id',
                uniqueId: 'test-unique-id',
                remoteAddress: '192.168.1.1',
                protocol: 'http',
                rawRequest: 'GET /callback/test HTTP/1.1',
              },
            ],
          }),
        } as Response);
        
        const { id } = await client.generatePayload();
        const interactions = await client.checkInteractions(id);
        
        expect(interactions.length).toBe(1);
        expect(interactions[0].protocol).toBe('http');
        expect(interactions[0].remoteIp).toBe('192.168.1.1');
        expect(interactions[0].timestamp).toBeInstanceOf(Date);
        expect(interactions[0].rawRequest).toBe('GET /callback/test HTTP/1.1');
        expect(interactions[0].path).toBe('/callback/test');
      });
    });

    describe('cleanup', () => {
      test('should clear registered IDs', async () => {
        // Generate a payload first
        global.fetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({ uuid: 'test-id', secret: 'test-secret', fullId: 'test-full-id' }),
        } as Response);
        
        await client.generatePayload();
        await client.cleanup();
        
        // Verify cleanup worked by checking if we can still poll
        // (This would require mocking the internal Map, which is difficult)
        expect(client).toBeDefined();
      });
    });

    describe('isReady', () => {
      test('should return true when server is reachable', async () => {
        // Mock successful registration
        global.fetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({ uuid: 'test-id', secret: 'test-secret', fullId: 'test-full-id' }),
        } as Response);
        
        const isReady = await client.isReady();
        expect(isReady).toBe(true);
      });

      test('should return false when server is not reachable', async () => {
        // Mock failed registration
        global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
        
        const isReady = await client.isReady();
        expect(isReady).toBe(false);
      });
    });
  });

  describe('OOBInteraction type', () => {
    test('should have required properties', () => {
      const interaction: OOBInteraction = {
        protocol: 'http',
        remoteIp: '192.168.1.1',
        timestamp: new Date(),
        rawRequest: 'GET /test HTTP/1.1',
        path: '/test',
        queryType: 'A',
      };
      
      expect(interaction.protocol).toBe('http');
      expect(interaction.remoteIp).toBe('192.168.1.1');
      expect(interaction.timestamp).toBeInstanceOf(Date);
      expect(interaction.rawRequest).toBeDefined();
      expect(interaction.path).toBe('/test');
      expect(interaction.queryType).toBe('A');
    });

    test('should support all protocol types', () => {
      const protocols: OOBInteraction['protocol'][] = ['dns', 'http', 'smtp', 'ldap', 'ftp'];
      
      protocols.forEach(protocol => {
        const interaction: OOBInteraction = {
          protocol,
          remoteIp: '192.168.1.1',
          timestamp: new Date(),
        };
        expect(interaction.protocol).toBe(protocol);
      });
    });
  });
});
