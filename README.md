# Shodan MCP Server

A Model Context Protocol (MCP) server that provides access to Shodan API functionality, allowing AI assistants to query information about internet-connected devices and services.

## Features

- **Host Information**: Get detailed information about specific IP addresses
- **Search Capabilities**: Search Shodan's database for devices and services
- **Network Scanning**: Scan network ranges (CIDR notation) for devices
- **SSL Certificate Information**: Get SSL certificate details for domains
- **IoT Device Search**: Find specific types of IoT devices

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Cyreslab-AI/shodan-mcp-server.git
   cd shodan-mcp-server
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Build the server:

   ```bash
   npm run build
   ```

4. Set up your Shodan API key:

   ```bash
   export SHODAN_API_KEY="your-api-key-here"
   ```

5. Start the server:
   ```bash
   npm start
   ```

## MCP Integration

This server can be integrated with Claude or other MCP-compatible AI assistants. To add it to Claude Desktop or Claude.app:

1. Add the server to your MCP settings:

   ```json
   {
     "mcpServers": {
       "shodan": {
         "command": "node",
         "args": ["/path/to/shodan-mcp-server/build/index.js"],
         "env": {
           "SHODAN_API_KEY": "your-api-key-here"
         }
       }
     }
   }
   ```

2. Restart Claude to load the new MCP server.

## Available Tools

### get_host_info

Get detailed information about a specific IP address.

**Parameters:**

- `ip` (required): IP address to look up
- `max_items` (optional): Maximum number of items to include in arrays (default: 5)
- `fields` (optional): List of fields to include in the results (e.g., ['ip_str', 'ports', 'location.country_name'])

### search_shodan

Search Shodan's database for devices and services.

**Parameters:**

- `query` (required): Shodan search query (e.g., 'apache country:US')
- `page` (optional): Page number for results pagination (default: 1)
- `facets` (optional): List of facets to include in the search results (e.g., ['country', 'org'])
- `max_items` (optional): Maximum number of items to include in arrays (default: 5)
- `fields` (optional): List of fields to include in the results (e.g., ['ip_str', 'ports', 'location.country_name'])
- `summarize` (optional): Whether to return a summary of the results instead of the full data (default: false)

### scan_network_range

Scan a network range (CIDR notation) for devices.

**Parameters:**

- `cidr` (required): Network range in CIDR notation (e.g., 192.168.1.0/24)
- `max_items` (optional): Maximum number of items to include in results (default: 5)
- `fields` (optional): List of fields to include in the results (e.g., ['ip_str', 'ports', 'location.country_name'])

### get_ssl_info

Get SSL certificate information for a domain.

**Parameters:**

- `domain` (required): Domain name to look up SSL certificates for (e.g., example.com)

### search_iot_devices

Search for specific types of IoT devices.

**Parameters:**

- `device_type` (required): Type of IoT device to search for (e.g., 'webcam', 'router', 'smart tv')
- `country` (optional): Optional country code to limit search (e.g., 'US', 'DE')
- `max_items` (optional): Maximum number of items to include in results (default: 5)

## Available Resources

- `shodan://host/{ip}`: Information about a specific IP address

## API Limitations

Some Shodan API endpoints require a paid membership. The following features are only available with a paid Shodan API key:

- Search functionality
- Network scanning
- SSL certificate lookup
- IoT device search

## License

MIT

## Developed by

[Cyreslab.ai](https://cyreslab.ai)
