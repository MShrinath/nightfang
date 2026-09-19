"""CLI entry point for NIGHTFANG."""
import asyncio
import sys
import argparse
import logging
from pathlib import Path
from typing import Optional

from ..core.orchestrator import NightfangOrchestrator


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


async def run_engagement(config_path: str, phase: str = 'full', engagement_id: Optional[str] = None):
    """Run an engagement."""
    orchestrator = NightfangOrchestrator(config_path, engagement_id)
    await orchestrator.initialize()
    
    try:
        if phase == 'full':
            await orchestrator.run_full_engagement()
        else:
            await orchestrator.run_single_phase(phase)
    finally:
        await orchestrator.telegram.close()


def main():
    parser = argparse.ArgumentParser(
        description='NIGHTFANG - Autonomous Penetration Testing Swarm',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nightfang start --config config/personal_engagement.yaml
  nightfang start --config config/engagement_template.yaml --phase recon
  nightfang start --config config/personal_engagement.yaml --phase webapp
  nightfang start --config config/personal_engagement.yaml --phase api
  nightfang start --config config/personal_engagement.yaml --phase network
  nightfang start --config config/personal_engagement.yaml --phase cloud
  nightfang start --config config/personal_engagement.yaml --phase ssl
  nightfang start --config config/personal_engagement.yaml --phase ai
  nightfang start --config config/personal_engagement.yaml --phase vuln
  nightfang start --config config/personal_engagement.yaml --phase payload
  nightfang start --config config/personal_engagement.yaml --phase hunt
  nightfang start --config config/personal_engagement.yaml --phase exploit
  nightfang start --config config/personal_engagement.yaml --phase report
        """
    )
    
    parser.add_argument('command', choices=['start', 'resume', 'status'], 
                       help='Command to execute')
    parser.add_argument('--config', '-c', required=True, 
                       help='Path to engagement configuration YAML')
    parser.add_argument('--phase', '-p', 
                       choices=['full', 'recon', 'active_recon', 'webapp', 'api', 'network', 'cloud', 'ssl', 'ai', 'vuln', 'payload', 'hunt', 'exploit', 'report'],
                       default='full', help='Phase to run (default: full)')
    parser.add_argument('--engagement-id', '-e', 
                       help='Engagement ID for resume')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    
    if args.command == 'start':
        asyncio.run(run_engagement(str(config_path), args.phase))
    elif args.command == 'resume':
        if not args.engagement_id:
            print("Error: --engagement-id required for resume")
            sys.exit(1)
        # TODO: Implement resume functionality
        print("Resume not yet implemented")
        sys.exit(1)
    elif args.command == 'status':
        # TODO: Implement status check
        print("Status check not yet implemented")
        sys.exit(1)


if __name__ == '__main__':
    main()