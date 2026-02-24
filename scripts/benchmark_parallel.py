#!/usr/bin/env python3
"""
FEPD Parallel Processing Benchmark Script

Compares serial vs parallel processing performance for forensic artifact parsing.
Helps determine optimal worker configuration for your system.

Usage:
    python benchmark_parallel.py [options]
    
    Options:
        --artifacts NUM     Number of test artifacts (default: 100)
        --workers NUM       Max workers to test (default: auto-detect)
        --runs NUM          Number of benchmark runs (default: 3)
        --output FILE       Save results to CSV (optional)

Example:
    # Basic benchmark
    python benchmark_parallel.py
    
    # Test with 500 artifacts and up to 8 workers
    python benchmark_parallel.py --artifacts 500 --workers 8
    
    # Export results
    python benchmark_parallel.py --output benchmark_results.csv

Author: FEPD Development Team
Version: 2.0.0
"""

import sys
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
import statistics
import psutil
import json

# Add FEPD to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.pipeline import ParsingWorker, ProgressAggregator


class ParallelBenchmark:
    """
    Benchmark suite for parallel processing performance.
    
    Tests various worker configurations and reports:
        - Execution time
        - Throughput (artifacts/sec)
        - CPU utilization
        - Memory usage
        - Speedup factor
        - Efficiency ratio
    """
    
    def __init__(self, num_artifacts: int = 100, num_runs: int = 3):
        """
        Initialize benchmark.
        
        Args:
            num_artifacts: Number of test artifacts to process
            num_runs: Number of times to run each configuration
        """
        self.num_artifacts = num_artifacts
        self.num_runs = num_runs
        self.results = []
        
        # Create synthetic test data
        self.test_tasks = self._create_test_tasks()
        
        print("=" * 80)
        print("FEPD PARALLEL PROCESSING BENCHMARK")
        print("=" * 80)
        print(f"Test artifacts: {num_artifacts}")
        print(f"Benchmark runs: {num_runs}")
        print(f"CPU cores: {mp.cpu_count()}")
        print(f"Total memory: {psutil.virtual_memory().total / (1024**3):.1f} GB")
        print("=" * 80)
        print()
    
    def _create_test_tasks(self) -> List[Dict[str, Any]]:
        """
        Create synthetic parsing tasks for benchmarking.
        
        Uses lightweight mock tasks that simulate parsing overhead
        without requiring actual forensic files.
        """
        tasks = []
        for i in range(self.num_artifacts):
            # Simulate different artifact types
            artifact_types = ['EVTX', 'Registry', 'Prefetch', 'MFT', 'Browser']
            task = {
                'artifact_id': i,
                'artifact_type': artifact_types[i % len(artifact_types)],
                'file_path': f'/mock/artifact_{i}.dat',
                'is_benchmark': True  # Flag for mock processing
            }
            tasks.append(task)
        return tasks
    
    def benchmark_serial(self) -> Dict[str, Any]:
        """
        Benchmark serial (single-threaded) processing.
        
        Returns:
            Dictionary with performance metrics
        """
        print("Benchmarking SERIAL processing...")
        
        times = []
        cpu_samples = []
        memory_samples = []
        
        for run in range(self.num_runs):
            # Start monitoring
            process = psutil.Process()
            start_mem = process.memory_info().rss / (1024**2)  # MB
            
            start_time = time.time()
            
            # Serial processing simulation
            events_processed = 0
            for task in self.test_tasks:
                # Simulate processing time
                time.sleep(0.001)  # 1ms per artifact (mock)
                events_processed += 10  # Mock event count
            
            elapsed = time.time() - start_time
            times.append(elapsed)
            
            # Sample CPU and memory
            cpu_samples.append(psutil.cpu_percent(interval=0.1))
            end_mem = process.memory_info().rss / (1024**2)
            memory_samples.append(end_mem - start_mem)
            
            print(f"  Run {run + 1}/{self.num_runs}: {elapsed:.2f}s")
        
        return {
            'mode': 'Serial',
            'workers': 1,
            'mean_time': statistics.mean(times),
            'stdev_time': statistics.stdev(times) if len(times) > 1 else 0,
            'throughput': self.num_artifacts / statistics.mean(times),
            'cpu_percent': statistics.mean(cpu_samples),
            'memory_mb': statistics.mean(memory_samples),
            'speedup': 1.0,
            'efficiency': 1.0
        }
    
    def benchmark_parallel(self, num_workers: int, baseline_time: float) -> Dict[str, Any]:
        """
        Benchmark parallel processing with specified worker count.
        
        Args:
            num_workers: Number of worker processes
            baseline_time: Serial processing time (for speedup calculation)
        
        Returns:
            Dictionary with performance metrics
        """
        print(f"Benchmarking PARALLEL processing ({num_workers} workers)...")
        
        times = []
        cpu_samples = []
        memory_samples = []
        
        for run in range(self.num_runs):
            process = psutil.Process()
            start_mem = process.memory_info().rss / (1024**2)
            
            start_time = time.time()
            
            # Parallel processing with ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                # Submit tasks (mock version just sleeps)
                futures = {
                    executor.submit(self._mock_parse_task, task): task
                    for task in self.test_tasks
                }
                
                # Wait for completion
                for future in as_completed(futures):
                    result = future.result()
            
            elapsed = time.time() - start_time
            times.append(elapsed)
            
            cpu_samples.append(psutil.cpu_percent(interval=0.1))
            end_mem = process.memory_info().rss / (1024**2)
            memory_samples.append(end_mem - start_mem)
            
            print(f"  Run {run + 1}/{self.num_runs}: {elapsed:.2f}s")
        
        mean_time = statistics.mean(times)
        speedup = baseline_time / mean_time
        efficiency = speedup / num_workers
        
        return {
            'mode': 'Parallel',
            'workers': num_workers,
            'mean_time': mean_time,
            'stdev_time': statistics.stdev(times) if len(times) > 1 else 0,
            'throughput': self.num_artifacts / mean_time,
            'cpu_percent': statistics.mean(cpu_samples),
            'memory_mb': statistics.mean(memory_samples),
            'speedup': speedup,
            'efficiency': efficiency
        }
    
    @staticmethod
    def _mock_parse_task(task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mock parsing task for benchmarking.
        
        Simulates CPU work without requiring actual files.
        """
        # Simulate parsing overhead
        time.sleep(0.001)  # 1ms per artifact
        
        return {
            'artifact_id': task['artifact_id'],
            'events': [{'mock': True}] * 10,
            'success': True,
            'error': None,
            'event_count': 10
        }
    
    def run_full_benchmark(self, max_workers: int = None) -> None:
        """
        Run complete benchmark suite.
        
        Tests serial and multiple parallel configurations.
        
        Args:
            max_workers: Maximum workers to test (None = CPU count)
        """
        if max_workers is None:
            max_workers = mp.cpu_count()
        
        # Baseline: Serial processing
        serial_result = self.benchmark_serial()
        self.results.append(serial_result)
        baseline_time = serial_result['mean_time']
        
        print()
        
        # Test multiple worker configurations
        worker_configs = [2, 4]
        if max_workers >= 8:
            worker_configs.extend([8, max_workers])
        elif max_workers > 4:
            worker_configs.append(max_workers)
        
        # Remove duplicates and sort
        worker_configs = sorted(set(w for w in worker_configs if w <= max_workers))
        
        for workers in worker_configs:
            parallel_result = self.benchmark_parallel(workers, baseline_time)
            self.results.append(parallel_result)
            print()
    
    def print_results(self) -> None:
        """Print benchmark results in formatted table."""
        print("=" * 100)
        print("BENCHMARK RESULTS")
        print("=" * 100)
        print()
        
        # Table header
        header = (
            f"{'Mode':<12} | "
            f"{'Workers':<8} | "
            f"{'Time (s)':<10} | "
            f"{'StdDev':<8} | "
            f"{'Throughput':<12} | "
            f"{'Speedup':<8} | "
            f"{'Efficiency':<10}"
        )
        print(header)
        print("-" * 100)
        
        # Table rows
        for result in self.results:
            row = (
                f"{result['mode']:<12} | "
                f"{result['workers']:<8} | "
                f"{result['mean_time']:<10.2f} | "
                f"{result['stdev_time']:<8.3f} | "
                f"{result['throughput']:<12.1f} | "
                f"{result['speedup']:<8.2f}x | "
                f"{result['efficiency']:<10.1%}"
            )
            print(row)
        
        print("-" * 100)
        print()
        
        # Find optimal configuration
        best = max(self.results[1:], key=lambda x: x['speedup'])  # Skip serial
        print(f"🏆 OPTIMAL CONFIGURATION: {best['workers']} workers")
        print(f"   Speedup: {best['speedup']:.2f}x faster than serial")
        print(f"   Efficiency: {best['efficiency']:.1%} per worker")
        print(f"   Throughput: {best['throughput']:.1f} artifacts/sec")
        print()
    
    def export_csv(self, output_path: Path) -> None:
        """
        Export results to CSV file.
        
        Args:
            output_path: Path to output CSV file
        """
        import csv
        
        with open(output_path, 'w', newline='') as f:
            fieldnames = [
                'mode', 'workers', 'mean_time', 'stdev_time',
                'throughput', 'speedup', 'efficiency',
                'cpu_percent', 'memory_mb'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)
        
        print(f"✅ Results exported to: {output_path}")
    
    def export_json(self, output_path: Path) -> None:
        """
        Export results to JSON file.
        
        Args:
            output_path: Path to output JSON file
        """
        with open(output_path, 'w') as f:
            json.dump({
                'benchmark_config': {
                    'num_artifacts': self.num_artifacts,
                    'num_runs': self.num_runs,
                    'cpu_cores': mp.cpu_count()
                },
                'results': self.results
            }, f, indent=2)
        
        print(f"✅ Results exported to: {output_path}")


def main():
    """Main entry point for benchmark script."""
    parser = argparse.ArgumentParser(
        description="Benchmark FEPD parallel processing performance"
    )
    parser.add_argument(
        '--artifacts',
        type=int,
        default=100,
        help='Number of test artifacts (default: 100)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=None,
        help='Maximum workers to test (default: auto-detect)'
    )
    parser.add_argument(
        '--runs',
        type=int,
        default=3,
        help='Number of benchmark runs (default: 3)'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=None,
        help='Save results to file (CSV or JSON based on extension)'
    )
    
    args = parser.parse_args()
    
    # Run benchmark
    benchmark = ParallelBenchmark(
        num_artifacts=args.artifacts,
        num_runs=args.runs
    )
    
    benchmark.run_full_benchmark(max_workers=args.workers)
    benchmark.print_results()
    
    # Export if requested
    if args.output:
        if args.output.suffix.lower() == '.json':
            benchmark.export_json(args.output)
        else:
            benchmark.export_csv(args.output)


if __name__ == '__main__':
    main()
