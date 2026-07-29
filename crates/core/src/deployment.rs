// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Enterprise Deployment & Infrastructure as Code (IaC) Engine (§8.4).
//!
//! Provides:
//! - Docker Compose stack specification generator (§8.4.1)
//! - Kubernetes Helm Chart template generator (§8.4.2)
//! - Air-gapped offline environment validator (§8.4.3)
//! - Ansible Sensor Fleet Deployment Playbook generator (§8.4.4)
//! - Terraform Infrastructure provisioning module generator (§8.4.5)

/// Deployment Mode (§8.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeploymentMode {
    OnlineCloud,
    AirGappedOffline,
}

/// Air-gapped Environment Validator (§8.4.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AirGappedConfig {
    pub is_air_gapped: bool,
    pub offline_maxmind_db_path: Option<String>,
    pub offline_ntp_server: Option<String>,
}

impl Default for AirGappedConfig {
    fn default() -> Self {
        Self {
            is_air_gapped: true,
            offline_maxmind_db_path: Some("/var/lib/netscope/GeoLite2-City.mmdb".to_string()),
            offline_ntp_server: Some("10.0.0.1".to_string()),
        }
    }
}

/// Enterprise Deployment Generator (§8.4).
#[derive(Debug, Default)]
pub struct DeploymentEngine;

impl DeploymentEngine {
    pub fn new() -> Self {
        Self
    }

    /// Generate Docker Compose Stack Manifest (§8.4.1).
    pub fn generate_docker_compose(&self) -> String {
        r#"version: '3.8'
services:
  netscope-server:
    image: netscope/server:latest
    ports:
      - "50051:50051"
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://netscope:password@db:5432/netscope
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=netscope
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=netscope
  redis:
    image: redis:7-alpine
"#.to_string()
    }

    /// Generate Kubernetes Helm Chart Values Manifest (§8.4.2).
    pub fn generate_helm_values(&self) -> String {
        r#"replicaCount: 3
image:
  repository: netscope/server
  tag: latest
service:
  type: ClusterIP
  port: 8080
resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 500m
    memory: 1Gi
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 20
"#.to_string()
    }

    /// Generate Ansible Sensor Fleet Playbook (§8.4.4).
    pub fn generate_ansible_playbook(&self) -> String {
        r#"- name: Deploy Netscope Sensor Fleet
  hosts: sensors
  become: yes
  tasks:
    - name: Install libpcap dependencies
      apt:
        name: libpcap-dev
        state: present
    - name: Deploy netscope-agent binary
      copy:
        src: /dist/netscope-agent
        dest: /usr/local/bin/netscope-agent
        mode: '0755'
    - name: Ensure netscope-agent service is running
      systemd:
        name: netscope-agent
        state: started
        enabled: yes
"#.to_string()
    }

    /// Generate Terraform Infrastructure Module (§8.4.5).
    pub fn generate_terraform_module(&self) -> String {
        r#"resource "aws_vpc" "netscope_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_subnet" "sensor_subnet" {
  vpc_id     = aws_vpc.netscope_vpc.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_ec2_traffic_mirror_target" "target" {
  network_interface_id = aws_instance.netscope_server.primary_network_interface_id
}
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_compose_and_helm() {
        let engine = DeploymentEngine::new();
        let compose = engine.generate_docker_compose();
        assert!(compose.contains("netscope-server"));
        assert!(compose.contains("postgres:15-alpine"));

        let helm = engine.generate_helm_values();
        assert!(helm.contains("replicaCount: 3"));
        assert!(helm.contains("netscope/server"));
    }

    #[test]
    fn test_ansible_and_terraform() {
        let engine = DeploymentEngine::new();
        let ansible = engine.generate_ansible_playbook();
        assert!(ansible.contains("Deploy Netscope Sensor Fleet"));
        assert!(ansible.contains("libpcap-dev"));

        let tf = engine.generate_terraform_module();
        assert!(tf.contains("aws_vpc"));
        assert!(tf.contains("aws_ec2_traffic_mirror_target"));
    }

    #[test]
    fn test_air_gapped_config() {
        let config = AirGappedConfig::default();
        assert!(config.is_air_gapped);
        assert!(config.offline_maxmind_db_path.is_some());
    }
}
