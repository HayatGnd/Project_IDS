"""
Flask API Application for SecureCorp Zero-Trust System
Provides REST endpoints for authentication and resource access.
"""

from flask import Flask, request, jsonify
from typing import Dict, Any
import json
from auth import get_kdc
from ressources import get_resource_server
from audit_logger import get_audit_logger

app = Flask(__name__)

# Initialize components
kdc = get_kdc()
resource_server = get_resource_server()
audit_logger = get_audit_logger()


@app.route('/login', methods=['POST'])
def login():
    """
    POST /login
    Authenticates user and issues TGT.
    
    Request body:
    {
        "username": "alice",
        "password": "password123"
    }
    
    Response:
    {
        "success": true,
        "tgt": "encrypted_tgt_string",
        "message": "Login successful"
    }
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({
                "success": False,
                "message": "Missing username or password"
            }), 400

        username = data['username']
        password = data['password']
        ip_address = request.remote_addr

        success, tgt, error_message = kdc.login(username, password, ip_address)

        if success:
            return jsonify({
                "success": True,
                "tgt": tgt,
                "message": "Login successful"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": error_message
            }), 401

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Login failed: {str(e)}"
        }), 500


@app.route('/request-ticket', methods=['POST'])
def request_ticket():
    """
    POST /request-ticket
    Requests service ticket using TGT.
    
    Request body:
    {
        "username": "alice",
        "tgt": "encrypted_tgt_string",
        "service": "resource-server",
        "nonce": "random_nonce_string"
    }
    
    Response:
    {
        "success": true,
        "service_ticket": "encrypted_ticket_string",
        "message": "Ticket issued"
    }
    """
    try:
        data = request.get_json()
        required_fields = ['username', 'tgt', 'service', 'nonce']
        
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                "success": False,
                "message": "Missing required fields: username, tgt, service, nonce"
            }), 400

        username = data['username']
        tgt = data['tgt']
        service = data['service']
        nonce = data['nonce']
        ip_address = request.remote_addr

        success, service_ticket, error_message = kdc.request_service_ticket(
            username, service, tgt, nonce, ip_address
        )

        if success:
            return jsonify({
                "success": True,
                "service_ticket": service_ticket,
                "message": "Service ticket issued"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": error_message
            }), 401

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Ticket request failed: {str(e)}"
        }), 500


@app.route('/resource/<resource_id>', methods=['GET'])
def get_resource(resource_id):
    """
    GET /resource/<resource_id>
    Access a specific resource.
    
    Headers:
    Authorization: Bearer <service_ticket>
    
    Response:
    {
        "success": true,
        "resource": {...},
        "message": "Resource accessed"
    }
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                "success": False,
                "message": "Missing or invalid Authorization header"
            }), 401

        service_ticket = auth_header.replace('Bearer ', '')
        ip_address = request.remote_addr

        success, resource, error_message = resource_server.get_resource(
            service_ticket, resource_id, ip_address
        )

        if success and resource:
            return jsonify({
                "success": True,
                "resource": resource,
                "message": "Resource accessed successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": error_message
            }), 403

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Resource access failed: {str(e)}"
        }), 500


@app.route('/resource', methods=['POST'])
def create_resource():
    """
    POST /resource
    Create a new resource.
    
    Headers:
    Authorization: Bearer <service_ticket>
    
    Request body:
    {
        "name": "New Document",
        "department": "IT",
        "classification": "public",
        "access_location": "any",
        "content": "Document content..."
    }
    
    Response:
    {
        "success": true,
        "resource": {...},
        "message": "Resource created"
    }
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                "success": False,
                "message": "Missing or invalid Authorization header"
            }), 401

        service_ticket = auth_header.replace('Bearer ', '')
        resource_data = request.get_json() or {}
        ip_address = request.remote_addr

        success, resource, error_message = resource_server.create_resource(
            service_ticket, resource_data, ip_address
        )

        if success and resource:
            return jsonify({
                "success": True,
                "resource": resource,
                "message": "Resource created successfully"
            }), 201
        else:
            return jsonify({
                "success": False,
                "message": error_message
            }), 403

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Resource creation failed: {str(e)}"
        }), 500


@app.route('/resource/<resource_id>', methods=['DELETE'])
def delete_resource(resource_id):
    """
    DELETE /resource/<resource_id>
    Delete a specific resource.
    
    Headers:
    Authorization: Bearer <service_ticket>
    
    Response:
    {
        "success": true,
        "resource": {...},
        "message": "Resource deleted"
    }
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                "success": False,
                "message": "Missing or invalid Authorization header"
            }), 401

        service_ticket = auth_header.replace('Bearer ', '')
        ip_address = request.remote_addr

        success, resource, error_message = resource_server.delete_resource(
            service_ticket, resource_id, ip_address
        )

        if success and resource:
            return jsonify({
                "success": True,
                "resource": resource,
                "message": "Resource deleted successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": error_message
            }), 403

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Resource deletion failed: {str(e)}"
        }), 500


@app.route('/resources', methods=['GET'])
def list_resources():
    """
    GET /resources
    List all accessible resources.
    
    Headers:
    Authorization: Bearer <service_ticket>
    
    Response:
    {
        "success": true,
        "resources": [...],
        "message": "Resources listed"
    }
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                "success": False,
                "message": "Missing or invalid Authorization header"
            }), 401

        service_ticket = auth_header.replace('Bearer ', '')
        ip_address = request.remote_addr

        success, resources, error_message = resource_server.list_resources(
            service_ticket, ip_address
        )

        if success and resources is not None:
            return jsonify({
                "success": True,
                "resources": resources,
                "message": "Resources listed successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": error_message
            }), 403

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Resource listing failed: {str(e)}"
        }), 500


@app.route('/audit-report', methods=['GET'])
def get_audit_report():
    """
    GET /audit-report
    Get security audit report.
    
    Response:
    {
        "total_events": 150,
        "critical_events": 5,
        "failed_logins": {"alice": 2, "bob": 1},
        "attack_events": 3
    }
    """
    try:
        report = audit_logger.generate_security_report()
        return jsonify(report), 200

    except Exception as e:
        return jsonify({
            "error": f"Failed to generate audit report: {str(e)}"
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "SecureCorp Zero-Trust API",
        "version": "1.0"
    }), 200


if __name__ == '__main__':
    print("Starting SecureCorp Zero-Trust API Server...")
    print("Available endpoints:")
    print("  POST /login")
    print("  POST /request-ticket")
    print("  GET /resource/<id>")
    print("  POST /resource")
    print("  DELETE /resource/<id>")
    print("  GET /resources")
    print("  GET /audit-report")
    print("  GET /health")
    app.run(debug=True, host='0.0.0.0', port=5000)