
import { DomExplorer, AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';
import { Page, Request } from 'playwright';

describe('DomExplorer Smart Exploration', () => {
  let domExplorer: DomExplorer;
  let mockPage: Page;

  beforeEach(() => {
    domExplorer = new DomExplorer();
    // Mock page with minimal implementation required by discoverUrlParameters/discoverLinks
    mockPage = {
      url: () => 'http://example.com',
      $$: jest.fn().mockResolvedValue([]), // No forms
      $$eval: jest.fn().mockResolvedValue([]), // No links
      context: () => ({
        cookies: jest.fn().mockResolvedValue([])
      })
    } as unknown as Page;
  });

  it('should discover API query parameters from XHR requests', async () => {
    const mockRequest = {
      url: () => 'http://example.com/api/users?search=test&limit=10',
      method: () => 'GET',
      resourceType: () => 'xhr',
      postData: () => null,
    } as unknown as Request;

    const surfaces = await domExplorer.explore(mockPage, [mockRequest]);
    
    const apiSurfaces = surfaces.filter(s => s.type === AttackSurfaceType.API_PARAM);
    expect(apiSurfaces.length).toBe(2);
    
    const searchParam = apiSurfaces.find(s => s.name === 'search');
    expect(searchParam).toBeDefined();
    expect(searchParam?.value).toBe('test');
    expect(searchParam?.context).toBe(InjectionContext.URL);
  });

  it('should discover JSON body parameters from POST requests', async () => {
    const mockRequest = {
      url: () => 'http://example.com/api/login',
      method: () => 'POST',
      resourceType: () => 'fetch',
      postData: () => '{"username": "admin", "password": "123", "config": {"debug": true}}',
      postDataJSON: () => ({
        username: "admin", 
        password: "123", 
        config: { debug: true }
      }),
    } as unknown as Request;

    const surfaces = await domExplorer.explore(mockPage, [mockRequest]);
    
    const jsonSurfaces = surfaces.filter(s => s.type === AttackSurfaceType.JSON_BODY);
    // Should find: username, password, config.debug
    expect(jsonSurfaces.length).toBe(3);
    
    const userParam = jsonSurfaces.find(s => s.name === 'username');
    expect(userParam).toBeDefined();
    expect(userParam?.value).toBe('admin');
    
    const nestedParam = jsonSurfaces.find(s => s.name === 'config.debug');
    expect(nestedParam).toBeDefined();
    expect(nestedParam?.value).toBe('true');
  });

  it('should ignore static resources', async () => {
    const mockRequest = {
      url: () => 'http://example.com/style.css',
      method: () => 'GET',
      resourceType: () => 'stylesheet',
    } as unknown as Request;

    const surfaces = await domExplorer.explore(mockPage, [mockRequest]);
    expect(surfaces.length).toBe(0);
  });
});
