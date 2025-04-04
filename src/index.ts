#!/usr/bin/env node

/**
 * Shodan MCP Server
 *
 * Developed by Cyreslab.ai (https://cyreslab.ai)
 * Contact: contact@cyreslab.ai
 * GitHub: https://github.com/Cyreslab-AI
 *
 * This server provides access to Shodan API functionality through the Model Context Protocol.
 * It allows AI assistants to query information about internet-connected devices and services,
 * enhancing cybersecurity research and threat intelligence capabilities.
 *
 * Copyright (c) 2025 Cyreslab.ai. All rights reserved.
 * Licensed under the MIT License.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListResourcesRequestSchema, ListToolsRequestSchema, McpError, ReadResourceRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";
import { z } from "zod";

// Get the Shodan API key from environment variables
const API_KEY = process.env.SHODAN_API_KEY || "";
if (!API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is required");
}

/**
 * Shodan API client class
 */
class ShodanClient {
  private axiosInstance: AxiosInstance;

  constructor(apiKey: string) {
    this.axiosInstance = axios.create({
      baseURL: "https://api.shodan.io",
      params: {
        key: apiKey
      }
    });
  }

  /**
   * Sample and limit response data to reduce token usage
   * @param data The data to sample
   * @param maxItems Maximum number of items to include in arrays
   * @param selectedFields Optional array of field paths to include
   * @returns Sampled data
   */
  private sampleResponse(data: any, maxItems: number = 5, selectedFields?: string[]): any {
    if (!data) return data;

    // Clone the data to avoid modifying the original
    const result = JSON.parse(JSON.stringify(data));

    // Sample matches array if it exists and is longer than maxItems
    if (result.matches && Array.isArray(result.matches) && result.matches.length > maxItems) {
      result.matches = result.matches.slice(0, maxItems);
      result._sample_note = `Response truncated to ${maxItems} matches. Original count: ${data.matches.length}`;
    }

    // Sample data array if it exists and is longer than maxItems
    if (result.data && Array.isArray(result.data) && result.data.length > maxItems) {
      result.data = result.data.slice(0, maxItems);
      result._sample_note = `Response truncated to ${maxItems} data items. Original count: ${data.data.length}`;
    }

    // Sample ports array if it exists and is longer than maxItems
    if (result.ports && Array.isArray(result.ports) && result.ports.length > maxItems) {
      result.ports = result.ports.slice(0, maxItems);
      if (!result._sample_note) {
        result._sample_note = `Ports truncated to ${maxItems} items. Original count: ${data.ports.length}`;
      }
    }

    // Filter fields if selectedFields is provided
    if (selectedFields && selectedFields.length > 0 && typeof result === 'object') {
      this.filterFields(result, selectedFields);
    }

    return result;
  }

  /**
   * Filter object to only include specified fields
   * @param obj Object to filter
   * @param fieldPaths Array of field paths (e.g. ['ip_str', 'ports', 'location.country_name'])
   */
  private filterFields(obj: any, fieldPaths: string[]): void {
    if (!obj || typeof obj !== 'object') return;

    // For arrays, apply filtering to each item
    if (Array.isArray(obj)) {
      obj.forEach(item => this.filterFields(item, fieldPaths));
      return;
    }

    // Create a map of top-level fields and nested paths
    const fieldMap = new Map<string, string[]>();

    fieldPaths.forEach(path => {
      const parts = path.split('.');
      const topField = parts[0];

      if (parts.length > 1) {
        // This is a nested path
        const nestedPath = parts.slice(1).join('.');
        if (!fieldMap.has(topField)) {
          fieldMap.set(topField, []);
        }
        fieldMap.get(topField)?.push(nestedPath);
      } else {
        // This is a top-level field
        fieldMap.set(topField, []);
      }
    });

    // Get all current keys in the object
    const currentKeys = Object.keys(obj);

    // Remove keys that aren't in our fieldMap
    currentKeys.forEach(key => {
      if (!fieldMap.has(key) && key !== '_sample_note') {
        delete obj[key];
      } else if (fieldMap.has(key) && fieldMap.get(key)?.length && obj[key] && typeof obj[key] === 'object') {
        // This key has nested paths to filter
        this.filterFields(obj[key], fieldMap.get(key) || []);
      }
    });
  }

  /**
   * Get information about a specific IP address
   */
  async getHostInfo(ip: string, maxItems: number = 5, selectedFields?: string[]): Promise<any> {
    try {
      const response = await this.axiosInstance.get(`/shodan/host/${ip}`);
      return this.sampleResponse(response.data, maxItems, selectedFields);
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        throw new McpError(
          ErrorCode.InternalError,
          `Shodan API error: ${error.response?.data?.error || error.message}`
        );
      }
      throw error;
    }
  }

  /**
   * Search Shodan's database
   */
  async search(query: string, page: number = 1, facets: string[] = [], maxItems: number = 5, selectedFields?: string[]): Promise<any> {
    try {
      const params: any = {
        query,
        page
      };

      if (facets.length > 0) {
        params.facets = facets.join(',');
      }

      const response = await this.axiosInstance.get("/shodan/host/search", { params });
      return this.sampleResponse(response.data, maxItems, selectedFields);
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          return {
            error: "Unauthorized: The Shodan search API requires a paid membership. Your API key does not have access to this endpoint.",
            message: "The search functionality requires a Shodan membership subscription with API access. Please upgrade your Shodan plan to use this feature.",
            status: 401
          };
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Shodan API error: ${error.response?.data?.error || error.message}`
        );
      }
      throw error;
    }
  }

  /**
   * Scan a network range (CIDR notation) for devices
   */
  async scanNetworkRange(cidr: string, maxItems: number = 5, selectedFields?: string[]): Promise<any> {
    try {
      // Convert CIDR to Shodan search query format
      const query = `net:${cidr}`;
      const response = await this.axiosInstance.get("/shodan/host/search", {
        params: { query }
      });
      return this.sampleResponse(response.data, maxItems, selectedFields);
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          return {
            error: "Unauthorized: The Shodan search API requires a paid membership. Your API key does not have access to this endpoint.",
            message: "The network scanning functionality requires a Shodan membership subscription with API access. Please upgrade your Shodan plan to use this feature.",
            status: 401
          };
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Shodan API error: ${error.response?.data?.error || error.message}`
        );
      }
      throw error;
    }
  }

  /**
   * Get SSL certificate information for a domain
   */
  async getSslInfo(domain: string): Promise<any> {
    try {
      // Use Shodan search to find SSL certificates for the domain
      const query = `ssl:${domain}`;
      const response = await this.axiosInstance.get("/shodan/host/search", {
        params: { query }
      });

      // Extract and format SSL certificate information
      const results = this.sampleResponse(response.data, 5);

      // Process the results to extract SSL certificate details
      if (results.matches && results.matches.length > 0) {
        const sslInfo = results.matches.map((match: any) => {
          if (match.ssl && match.ssl.cert) {
            return {
              ip: match.ip_str,
              port: match.port,
              subject: match.ssl.cert.subject,
              issuer: match.ssl.cert.issuer,
              expires: match.ssl.cert.expires,
              issued: match.ssl.cert.issued,
              fingerprint: match.ssl.cert.fingerprint,
              cipher: match.ssl.cipher,
              version: match.ssl.version
            };
          }
          return null;
        }).filter(Boolean);

        return {
          total: sslInfo.length,
          certificates: sslInfo
        };
      }

      return { total: 0, certificates: [] };
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          return {
            error: "Unauthorized: The Shodan search API requires a paid membership. Your API key does not have access to this endpoint.",
            message: "The SSL certificate lookup functionality requires a Shodan membership subscription with API access. Please upgrade your Shodan plan to use this feature.",
            status: 401
          };
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Shodan API error: ${error.response?.data?.error || error.message}`
        );
      }
      throw error;
    }
  }

  /**
   * Search for specific types of IoT devices
   */
  async searchIotDevices(deviceType: string, country?: string, maxItems: number = 5): Promise<any> {
    try {
      // Build query based on device type and optional country
      let query = `"${deviceType}"`;
      if (country) {
        query += ` country:${country}`;
      }

      const response = await this.axiosInstance.get("/shodan/host/search", {
        params: { query }
      });

      const results = this.sampleResponse(response.data, maxItems);

      // Extract relevant IoT device information
      if (results.matches && results.matches.length > 0) {
        const devices = results.matches.map((match: any) => {
          return {
            ip: match.ip_str,
            port: match.port,
            organization: match.org,
            location: match.location,
            hostnames: match.hostnames,
            product: match.product,
            version: match.version,
            timestamp: match.timestamp
          };
        });

        return {
          total_found: results.total,
          sample_size: devices.length,
          devices: devices
        };
      }

      return { total_found: 0, devices: [] };
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          return {
            error: "Unauthorized: The Shodan search API requires a paid membership. Your API key does not have access to this endpoint.",
            message: "The IoT device search functionality requires a Shodan membership subscription with API access. Please upgrade your Shodan plan to use this feature.",
            status: 401
          };
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Shodan API error: ${error.response?.data?.error || error.message}`
        );
      }
      throw error;
    }
  }

  /**
   * Generate a summary of search results
   */
  summarizeResults(data: any): any {
    if (!data || !data.matches || !Array.isArray(data.matches)) {
      return { error: "No valid data to summarize" };
    }

    // Count countries
    const countries = new Map<string, number>();
    data.matches.forEach((match: any) => {
      if (match.location && match.location.country_name) {
        const country = match.location.country_name;
        countries.set(country, (countries.get(country) || 0) + 1);
      }
    });

    // Count organizations
    const organizations = new Map<string, number>();
    data.matches.forEach((match: any) => {
      if (match.org) {
        const org = match.org;
        organizations.set(org, (organizations.get(org) || 0) + 1);
      }
    });

    // Count ports
    const ports = new Map<number, number>();
    data.matches.forEach((match: any) => {
      if (match.port) {
        const port = match.port;
        ports.set(port, (ports.get(port) || 0) + 1);
      }
    });

    // Convert maps to sorted arrays
    const topCountries = Array.from(countries.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }));

    const topOrganizations = Array.from(organizations.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }));

    const topPorts = Array.from(ports.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([port, count]) => ({ port, count }));

    return {
      total_results: data.total,
      sample_size: data.matches.length,
      top_countries: topCountries,
      top_organizations: topOrganizations,
      top_ports: topPorts
    };
  }
}

/**
 * Create and configure the Shodan MCP server
 */
async function main() {
  // Create Shodan client
  const shodanClient = new ShodanClient(API_KEY);

  // Create MCP server
  const server = new Server(
    {
      name: "mcp-shodan-server",
      version: "0.2.0"
    },
    {
      capabilities: {
        resources: {},
        tools: {},
      },
    }
  );

  // Set up resource handlers
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: [
        {
          uri: "shodan://host/example",
          name: "Host Information",
          description: "Information about a specific IP address from Shodan",
          mimeType: "application/json"
        }
      ]
    };
  });

  server.setRequestHandler(ReadResourceRequestSchema, async (request: any) => {
    const uri = request.params.uri;

    // Host information resource
    const hostMatch = uri.match(/^shodan:\/\/host\/([^/]+)$/);
    if (hostMatch) {
      const ip = decodeURIComponent(hostMatch[1]);
      try {
        const hostInfo = await shodanClient.getHostInfo(ip);
        return {
          contents: [{
            uri: uri,
            text: JSON.stringify(hostInfo, null, 2),
            mimeType: "application/json"
          }]
        };
      } catch (error) {
        throw new McpError(
          ErrorCode.InternalError,
          `Error getting host info: ${(error as Error).message}`
        );
      }
    }

    throw new McpError(
      ErrorCode.InvalidRequest,
      `Invalid URI format: ${uri}`
    );
  });

  // Set up tool handlers
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "get_host_info",
          description: "Get detailed information about a specific IP address",
          inputSchema: {
            type: "object",
            properties: {
              ip: {
                type: "string",
                description: "IP address to look up"
              },
              max_items: {
                type: "number",
                description: "Maximum number of items to include in arrays (default: 5)"
              },
              fields: {
                type: "array",
                items: {
                  type: "string"
                },
                description: "List of fields to include in the results (e.g., ['ip_str', 'ports', 'location.country_name'])"
              }
            },
            required: ["ip"]
          }
        },
        {
          name: "search_shodan",
          description: "Search Shodan's database for devices and services",
          inputSchema: {
            type: "object",
            properties: {
              query: {
                type: "string",
                description: "Shodan search query (e.g., 'apache country:US')"
              },
              page: {
                type: "number",
                description: "Page number for results pagination (default: 1)"
              },
              facets: {
                type: "array",
                items: {
                  type: "string"
                },
                description: "List of facets to include in the search results (e.g., ['country', 'org'])"
              },
              max_items: {
                type: "number",
                description: "Maximum number of items to include in arrays (default: 5)"
              },
              fields: {
                type: "array",
                items: {
                  type: "string"
                },
                description: "List of fields to include in the results (e.g., ['ip_str', 'ports', 'location.country_name'])"
              },
              summarize: {
                type: "boolean",
                description: "Whether to return a summary of the results instead of the full data (default: false)"
              }
            },
            required: ["query"]
          }
        },
        {
          name: "scan_network_range",
          description: "Scan a network range (CIDR notation) for devices",
          inputSchema: {
            type: "object",
            properties: {
              cidr: {
                type: "string",
                description: "Network range in CIDR notation (e.g., 192.168.1.0/24)"
              },
              max_items: {
                type: "number",
                description: "Maximum number of items to include in results (default: 5)"
              },
              fields: {
                type: "array",
                items: {
                  type: "string"
                },
                description: "List of fields to include in the results (e.g., ['ip_str', 'ports', 'location.country_name'])"
              }
            },
            required: ["cidr"]
          }
        },
        {
          name: "get_ssl_info",
          description: "Get SSL certificate information for a domain",
          inputSchema: {
            type: "object",
            properties: {
              domain: {
                type: "string",
                description: "Domain name to look up SSL certificates for (e.g., example.com)"
              }
            },
            required: ["domain"]
          }
        },
        {
          name: "search_iot_devices",
          description: "Search for specific types of IoT devices",
          inputSchema: {
            type: "object",
            properties: {
              device_type: {
                type: "string",
                description: "Type of IoT device to search for (e.g., 'webcam', 'router', 'smart tv')"
              },
              country: {
                type: "string",
                description: "Optional country code to limit search (e.g., 'US', 'DE')"
              },
              max_items: {
                type: "number",
                description: "Maximum number of items to include in results (default: 5)"
              }
            },
            required: ["device_type"]
          }
        }
      ]
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
    switch (request.params.name) {
      case "get_host_info": {
        const ip = String(request.params.arguments?.ip);
        if (!ip) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "IP address is required"
          );
        }

        const maxItems = Number(request.params.arguments?.max_items) || 5;
        const fields = Array.isArray(request.params.arguments?.fields)
          ? request.params.arguments?.fields.map(String)
          : undefined;

        try {
          const hostInfo = await shodanClient.getHostInfo(ip, maxItems, fields);
          return {
            content: [{
              type: "text",
              text: JSON.stringify(hostInfo, null, 2)
            }]
          };
        } catch (error) {
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `Error getting host info: ${(error as Error).message}`
          );
        }
      }

      case "search_shodan": {
        const query = String(request.params.arguments?.query);
        if (!query) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Search query is required"
          );
        }

        const page = Number(request.params.arguments?.page) || 1;
        const facets = Array.isArray(request.params.arguments?.facets)
          ? request.params.arguments?.facets.map(String)
          : [];
        const maxItems = Number(request.params.arguments?.max_items) || 5;
        const fields = Array.isArray(request.params.arguments?.fields)
          ? request.params.arguments?.fields.map(String)
          : undefined;
        const summarize = Boolean(request.params.arguments?.summarize);

        try {
          const searchResults = await shodanClient.search(query, page, facets, maxItems, fields);

          // Check if we got an error response from the search method
          if (searchResults.error && searchResults.status === 401) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify(searchResults, null, 2)
              }]
            };
          }

          if (summarize) {
            const summary = shodanClient.summarizeResults(searchResults);
            return {
              content: [{
                type: "text",
                text: JSON.stringify(summary, null, 2)
              }]
            };
          }

          return {
            content: [{
              type: "text",
              text: JSON.stringify(searchResults, null, 2)
            }]
          };
        } catch (error) {
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `Error searching Shodan: ${(error as Error).message}`
          );
        }
      }

      case "scan_network_range": {
        const cidr = String(request.params.arguments?.cidr);
        if (!cidr) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "CIDR notation is required"
          );
        }

        const maxItems = Number(request.params.arguments?.max_items) || 5;
        const fields = Array.isArray(request.params.arguments?.fields)
          ? request.params.arguments?.fields.map(String)
          : undefined;

        try {
          const scanResults = await shodanClient.scanNetworkRange(cidr, maxItems, fields);

          // Check if we got an error response from the scan method
          if (scanResults.error && scanResults.status === 401) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify(scanResults, null, 2)
              }]
            };
          }

          return {
            content: [{
              type: "text",
              text: JSON.stringify(scanResults, null, 2)
            }]
          };
        } catch (error) {
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `Error scanning network range: ${(error as Error).message}`
          );
        }
      }

      case "get_ssl_info": {
        const domain = String(request.params.arguments?.domain);
        if (!domain) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Domain name is required"
          );
        }

        try {
          const sslInfo = await shodanClient.getSslInfo(domain);

          // Check if we got an error response from the SSL info method
          if (sslInfo.error && sslInfo.status === 401) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify(sslInfo, null, 2)
              }]
            };
          }

          return {
            content: [{
              type: "text",
              text: JSON.stringify(sslInfo, null, 2)
            }]
          };
        } catch (error) {
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `Error getting SSL certificate information: ${(error as Error).message}`
          );
        }
      }

      case "search_iot_devices": {
        const deviceType = String(request.params.arguments?.device_type);
        if (!deviceType) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "Device type is required"
          );
        }

        const country = request.params.arguments?.country
          ? String(request.params.arguments.country)
          : undefined;
        const maxItems = Number(request.params.arguments?.max_items) || 5;

        try {
          const iotDevices = await shodanClient.searchIotDevices(deviceType, country, maxItems);

          // Check if we got an error response from the IoT devices search method
          if (iotDevices.error && iotDevices.status === 401) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify(iotDevices, null, 2)
              }]
            };
          }

          return {
            content: [{
              type: "text",
              text: JSON.stringify(iotDevices, null, 2)
            }]
          };
        } catch (error) {
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `Error searching for IoT devices: ${(error as Error).message}`
          );
        }
      }

      default:
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${request.params.name}`
        );
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Shodan MCP server running on stdio");
}

// Run the server
main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
