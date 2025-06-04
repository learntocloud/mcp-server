#!/usr/bin/env python3
"""
API Key Management Script for MCP Server

This script helps manage API keys stored in Azure Table Storage.
It can create, list, activate/deactivate, and delete API keys.
"""

import os
import sys
import uuid
from datetime import datetime
import argparse
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceExistsError, HttpResponseError


class APIKeyManager:
    def __init__(self):
        self.table_client = None
        self._initialize_table_client()
    
    def _initialize_table_client(self):
        """Initialize Azure Table Storage client."""
        # Try to use storage account name with managed identity first
        storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
        if storage_account_name:
            try:
                credential = DefaultAzureCredential()
                table_service = TableServiceClient(
                    endpoint=f"https://{storage_account_name}.table.core.windows.net",
                    credential=credential
                )
                print(f"Connected to storage account: {storage_account_name}")
            except Exception as e:
                print(f"Failed to use managed identity: {e}")
                # Fall back to connection string
                connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                if connection_string:
                    table_service = TableServiceClient.from_connection_string(
                        conn_str=connection_string
                    )
                    print("Using connection string")
                else:
                    raise
        else:
            # Use connection string
            connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
            if not connection_string:
                print("Error: No Azure Storage configuration found.")
                print("Set either AZURE_STORAGE_ACCOUNT_NAME or AZURE_STORAGE_CONNECTION_STRING")
                sys.exit(1)
            
            table_service = TableServiceClient.from_connection_string(
                conn_str=connection_string
            )
            print("Using connection string")
        
        # Get or create the api_keys table
        self.table_client = table_service.get_table_client("apikeys")
        
        # Create table if it doesn't exist
        try:
            table_service.create_table("apikeys")
            print("Created apikeys table")
        except ResourceExistsError:
            print("Using existing apikeys table")
    
    def create_key(self, description: str, key_prefix: str = "mcp") -> str:
        """Create a new API key."""
        # Generate a secure random key
        key_id = uuid.uuid4().hex
        api_key = f"{key_prefix}_{key_id}"
        
        entity = {
            "PartitionKey": "keys",
            "RowKey": api_key,
            "active": True,
            "created": datetime.utcnow().isoformat(),
            "description": description,
            "usage_count": 0
        }
        
        try:
            self.table_client.create_entity(entity)
            print(f"Created API key: {api_key}")
            print(f"Description: {description}")
            return api_key
        except Exception as e:
            print(f"Error creating API key: {e}")
            return None
    
    def list_keys(self):
        """List all API keys."""
        try:
            entities = self.table_client.list_entities()
            print("\nAPI Keys:")
            print("-" * 100)
            print(f"{'Key (first 16 chars)':<20} {'Active':<8} {'Created':<20} {'Last Used':<20} {'Usage':<8} {'Description':<30}")
            print("-" * 100)
            
            for entity in entities:
                key_preview = entity['RowKey'][:16] + "..."
                active = "Yes" if entity.get('active', False) else "No"
                created = entity.get('created', 'Unknown')[:19]
                last_used = entity.get('last_used', 'Never')[:19]
                usage = entity.get('usage_count', 0)
                description = entity.get('description', '')[:30]
                
                print(f"{key_preview:<20} {active:<8} {created:<20} {last_used:<20} {usage:<8} {description:<30}")
        except Exception as e:
            print(f"Error listing keys: {e}")
    
    def toggle_key(self, api_key: str, active: bool):
        """Activate or deactivate an API key."""
        try:
            entity = self.table_client.get_entity(partition_key="keys", row_key=api_key)
            entity['active'] = active
            self.table_client.update_entity(entity, mode='merge')
            status = "activated" if active else "deactivated"
            print(f"Successfully {status} key: {api_key}")
        except HttpResponseError as e:
            if e.status_code == 404:
                print(f"API key not found: {api_key}")
            else:
                print(f"Error updating key: {e}")
        except Exception as e:
            print(f"Error updating key: {e}")
    
    def delete_key(self, api_key: str):
        """Delete an API key."""
        try:
            self.table_client.delete_entity(partition_key="keys", row_key=api_key)
            print(f"Successfully deleted key: {api_key}")
        except HttpResponseError as e:
            if e.status_code == 404:
                print(f"API key not found: {api_key}")
            else:
                print(f"Error deleting key: {e}")
        except Exception as e:
            print(f"Error deleting key: {e}")
    
    def show_key_details(self, api_key: str):
        """Show detailed information about a specific API key."""
        try:
            entity = self.table_client.get_entity(partition_key="keys", row_key=api_key)
            print(f"\nAPI Key Details:")
            print(f"Key: {entity['RowKey']}")
            print(f"Active: {'Yes' if entity.get('active', False) else 'No'}")
            print(f"Created: {entity.get('created', 'Unknown')}")
            print(f"Last Used: {entity.get('last_used', 'Never')}")
            print(f"Usage Count: {entity.get('usage_count', 0)}")
            print(f"Description: {entity.get('description', '')}")
        except HttpResponseError as e:
            if e.status_code == 404:
                print(f"API key not found: {api_key}")
            else:
                print(f"Error retrieving key: {e}")
        except Exception as e:
            print(f"Error retrieving key: {e}")
    
    def list_registrations(self):
        """List all self-registrations from the registrations table."""
        try:
            # Get registrations table  
            storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
            if storage_account_name:
                try:
                    credential = DefaultAzureCredential()
                    table_service = TableServiceClient(
                        endpoint=f"https://{storage_account_name}.table.core.windows.net",
                        credential=credential
                    )
                except Exception:
                    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                    if connection_string:
                        table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
                    else:
                        raise
            else:
                connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                if not connection_string:
                    print("Error: No Azure Storage configuration found.")
                    return
                table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
            
            registrations_table = table_service.get_table_client("registrations")
            entities = registrations_table.list_entities()
            
            print("\nSelf-Registrations:")
            print("-" * 120)
            print(f"{'Email Hash':<20} {'Project Name':<25} {'GitHub Repo':<25} {'Created':<20} {'API Key Preview':<20}")
            print("-" * 120)
            
            for entity in entities:
                email_hash = entity['RowKey'][:16] + "..."
                project = entity.get('project_name', '')[:25]
                repo = entity.get('github_repo', '')[:25]
                created = entity.get('created', 'Unknown')[:19]
                key_preview = entity.get('api_key_preview', '')
                
                print(f"{email_hash:<20} {project:<25} {repo:<25} {created:<20} {key_preview:<20}")
                
        except Exception as e:
            print(f"Error listing registrations: {e}")
    
    def show_registration_stats(self):
        """Show registration statistics."""
        try:
            # Get registrations table
            storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
            if storage_account_name:
                try:
                    credential = DefaultAzureCredential()
                    table_service = TableServiceClient(
                        endpoint=f"https://{storage_account_name}.table.core.windows.net",
                        credential=credential
                    )
                except Exception:
                    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                    if connection_string:
                        table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
                    else:
                        raise
            else:
                connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                if not connection_string:
                    print("Error: No Azure Storage configuration found.")
                    return
                table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
            
            registrations_table = table_service.get_table_client("registrations")
            entities = list(registrations_table.list_entities())
            
            print(f"\nRegistration Statistics:")
            print(f"Total registrations: {len(entities)}")
            
            active_registrations = sum(1 for e in entities if e.get('active', False))
            print(f"Active registrations: {active_registrations}")
            
            # Show recent registrations
            recent = sorted(entities, key=lambda x: x.get('created', ''), reverse=True)[:5]
            print(f"\nRecent registrations:")
            for reg in recent:
                project = reg.get('project_name', 'Unknown')
                created = reg.get('created', 'Unknown')[:19]
                print(f"  - {project} ({created})")
            
        except Exception as e:
            print(f"Error getting registration stats: {e}")


def main():
    parser = argparse.ArgumentParser(description="Manage API keys for MCP Server")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new API key')
    create_parser.add_argument('description', help='Description for the API key')
    create_parser.add_argument('--prefix', default='mcp', help='Prefix for the API key (default: mcp)')
    
    # List command
    subparsers.add_parser('list', help='List all API keys')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show details of a specific API key')
    show_parser.add_argument('key', help='The API key to show')
    
    # Activate command
    activate_parser = subparsers.add_parser('activate', help='Activate an API key')
    activate_parser.add_argument('key', help='The API key to activate')
    
    # Deactivate command
    deactivate_parser = subparsers.add_parser('deactivate', help='Deactivate an API key')
    deactivate_parser.add_argument('key', help='The API key to deactivate')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete an API key')
    delete_parser.add_argument('key', help='The API key to delete')
    
    # Registration management commands
    subparsers.add_parser('list-registrations', help='List all self-registrations')
    subparsers.add_parser('registration-stats', help='Show registration statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize the manager
    manager = APIKeyManager()
    
    # Execute the command
    if args.command == 'create':
        api_key = manager.create_key(args.description, args.prefix)
        if api_key:
            print(f"\nIMPORTANT: Save this API key securely. It won't be shown again in full.")
            print(f"API Key: {api_key}")
    elif args.command == 'list':
        manager.list_keys()
    elif args.command == 'show':
        manager.show_key_details(args.key)
    elif args.command == 'activate':
        manager.toggle_key(args.key, True)
    elif args.command == 'deactivate':
        manager.toggle_key(args.key, False)
    elif args.command == 'delete':
        manager.delete_key(args.key)
    elif args.command == 'list-registrations':
        manager.list_registrations()
    elif args.command == 'registration-stats':
        manager.show_registration_stats()


if __name__ == "__main__":
    main()