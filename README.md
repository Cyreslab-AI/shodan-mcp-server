# Shodan MCP Server

A Model Context Protocol server that provides access to Shodan API functionality, developed by [Cyreslab.ai](https://cyreslab.ai). This server enables AI assistants like Claude to query information about internet-connected devices and services, enhancing cybersecurity research and threat intelligence capabilities.

**GitHub Repository**: [https://github.com/Cyreslab-AI](https://github.com/Cyreslab-AI)
**Contact**: [contact@cyreslab.ai](mailto:contact@cyreslab.ai)

## Features

- **Host Information Lookup**: Get detailed information about a specific IP address
- **Search Functionality**: Search Shodan's database for devices and services using various filters
- **Vulnerability Information**: Get details about specific CVE vulnerabilities
- **Result Summarization**: Generate concise summaries of search results
- **Response Sampling**: Automatically limit response size to reduce token usage
- **Field Selection**: Filter results to include only specific fields

## Installation

### Prerequisites

- Node.js (v16 or higher)
- npm (v7 or higher)

### Installation Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/Cyreslab-AI/shodan-mcp-server.git
   cd shodan-mcp-server
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Build the project:

   ```bash
   npm run build
   ```

4. Configure your Shodan API key:
   - Create a `.env` file in the root directory
   - Add your Shodan API key: `SHODAN_API_KEY=your_api_key_here`
   - Or set it as an environment variable when running the server

### MCP Configuration

To use this server with Claude or other MCP-compatible assistants, add it to your MCP configuration:

```json
{
  "mcpServers": {
    "mcp-shodan-server": {
      "command": "node",
      "args": ["/path/to/shodan-mcp-server/build/index.js"],
      "env": {
        "SHODAN_API_KEY": "YOUR_SHODAN_API_KEY_HERE"
      }
    }
  }
}
```

## Usage

### Get Host Information

Use the `get_host_info` tool to retrieve detailed information about a specific IP address:

```
<use_mcp_tool>
<server_name>mcp-shodan-server</server_name>
<tool_name>get_host_info</tool_name>
<arguments>
{
  "ip": "8.8.8.8"
}
</arguments>
</use_mcp_tool>
```

With field selection and response sampling:

```
<use_mcp_tool>
<server_name>mcp-shodan-server</server_name>
<tool_name>get_host_info</tool_name>
<arguments>
{
  "ip": "8.8.8.8",
  "max_items": 3,
  "fields": ["ip_str", "ports", "hostnames", "location.country_name"]
}
</arguments>
</use_mcp_tool>
```

### Search Shodan

Use the `search_shodan` tool to search Shodan's database for devices and services:

```
<use_mcp_tool>
<server_name>mcp-shodan-server</server_name>
<tool_name>search_shodan</tool_name>
<arguments>
{
  "query": "apache country:US",
  "page": 1,
  "facets": ["country", "org"]
}
</arguments>
</use_mcp_tool>
```

With result summarization:

```
<use_mcp_tool>
<server_name>mcp-shodan-server</server_name>
<tool_name>search_shodan</tool_name>
<arguments>
{
  "query": "apache country:US",
  "summarize": true
}
</arguments>
</use_mcp_tool>
```

### Get Vulnerability Information

Use the `get_vulnerabilities` tool to retrieve information about a specific CVE:

```
<use_mcp_tool>
<server_name>mcp-shodan-server</server_name>
<tool_name>get_vulnerabilities</tool_name>
<arguments>
{
  "cve": "CVE-2021-44228"
}
</arguments>
</use_mcp_tool>
```

## Search Query Examples

- `apache country:US`: Find Apache servers in the United States
- `port:22 country:DE`: Find SSH servers in Germany
- `webcam has_screenshot:true`: Find webcams with screenshots
- `org:"Microsoft" product:"Windows"`: Find Microsoft Windows devices
- `ssl:Google`: Find SSL certificates issued to Google

## Advanced Usage

### Pagination

For search results with many matches, you can paginate through the results by specifying the `page` parameter:

```json
{
  "query": "apache country:US",
  "page": 2
}
```

### Facets

Facets allow you to get summary information about the search results. For example, you can get a breakdown of the countries or organizations in the search results:

```json
{
  "query": "apache",
  "facets": ["country", "org"]
}
```

Common facets include:

- `country`: Country code
- `org`: Organization
- `domain`: Domain name
- `port`: Port number
- `asn`: Autonomous System Number
- `os`: Operating System

### Response Sampling

To reduce token usage, all responses are automatically sampled to include a limited number of items in arrays. You can control this with the `max_items` parameter:

```json
{
  "query": "apache country:US",
  "max_items": 10
}
```

### Field Selection

You can specify which fields to include in the results using the `fields` parameter:

```json
{
  "query": "apache country:US",
  "fields": ["ip_str", "port", "org", "location.country_name"]
}
```

This supports nested fields using dot notation (e.g., `location.country_name`).

### Result Summarization

For search results, you can request a summary instead of the full data:

```json
{
  "query": "apache country:US",
  "summarize": true
}
```

This will return:

- Total result count
- Top 5 countries
- Top 5 organizations
- Top 5 ports

## Future Enhancements

Future versions of this server will include:

- **Network Range Scanning**: Analyze entire CIDR ranges for security assessment
- **Advanced Vulnerability Correlation**: Link CVEs with affected devices and potential exploits
- **Historical Data Analysis**: Track changes in device exposure over time
- **Internet Maps & Real-time Data**: Visualize internet-wide technology deployments
- **Custom Filters**: Create and save specialized filters for specific technologies
- **Threat Intelligence Integration**: Correlate Shodan data with threat feeds
- **Reporting Capabilities**: Generate comprehensive security reports
- **API Rate Limit Management**: Smart handling of API quotas and rate limits

Have feature suggestions or found a bug? Please open an issue on our [GitHub repository](https://github.com/Cyreslab-AI) or contact us directly at [contact@cyreslab.ai](mailto:contact@cyreslab.ai).
