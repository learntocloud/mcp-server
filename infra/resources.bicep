param location string
param resourceToken string
param tags object

// Storage account for API keys (ensure name is 3-24 chars, lowercase/numbers only)
var storageAccountName = 'stmcp${toLower(take(resourceToken, 15))}'

resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
  }
}

resource web 'Microsoft.Web/sites@2022-03-01' = {
  name: 'web-${resourceToken}'
  location: location
  tags: union(tags, { 'azd-service-name': 'web' })
  kind: 'app,linux'
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.11'
      ftpsState: 'Disabled'
      appCommandLine: 'python3 -m gunicorn main:app -k uvicorn.workers.UvicornWorker'
    }
    httpsOnly: true
  }
  identity: {
    type: 'SystemAssigned'
  }

  resource appSettings 'config' = {
    name: 'appsettings'
    properties: {
      SCM_DO_BUILD_DURING_DEPLOYMENT: 'true'
      AZURE_STORAGE_ACCOUNT_NAME: storageAccount.name
      MCP_AUTH_TOKEN: ''  // Optional fallback token - set in Azure Portal if needed
      RATE_LIMIT_REQUESTS: '1000'  // Max requests per window
      RATE_LIMIT_WINDOW: '3600'    // Window in seconds (1 hour)
      REGISTRATION_RATE_LIMIT: '5'  // Max registrations per email per day
      REGISTRATION_WINDOW_HOURS: '24'  // Registration rate limit window
      CTF_KEY_EXPIRY_DAYS: ''  // Optional: Set to number of days for key expiration
      PYTHONPATH: '/home/site/wwwroot/src'
    }
  }

  resource logs 'config' = {
    name: 'logs'
    properties: {
      applicationLogs: {
        fileSystem: {
          level: 'Verbose'
        }
      }
      detailedErrorMessages: {
        enabled: true
      }
      failedRequestsTracing: {
        enabled: true
      }
      httpLogs: {
        fileSystem: {
          enabled: true
          retentionInDays: 1
          retentionInMb: 35
        }
      }
    }
  }
}
resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'app-${resourceToken}'
  location: location
  sku: {
    name: 'B1'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

// Role assignment: Allow App Service to access Storage Account
resource storageTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, web.name, 'StorageTableDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3') // Storage Table Data Contributor
    principalId: web.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output WEB_URI string = 'https://${web.properties.defaultHostName}'
output STORAGE_ACCOUNT_NAME string = storageAccount.name
