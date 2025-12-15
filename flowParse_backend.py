# FlowParse - Network Protocol Grammar Discovery using ML

import numpy as np
import pandas as pd
from scapy.all import sniff, rdpcap, wrpcap
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter, defaultdict
import re
import json
import pickle
from typing import List, Dict, Tuple, Any
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    """Handle packet capture and initial data extraction"""
    
    def __init__(self):
        self.packets = []
        self.payloads = []
    
    def capture_live_traffic(self, count=1000, filter_rule="tcp"):
        """Capture live network traffic"""
        logger.info(f"Starting live capture of {count} packets with filter: {filter_rule}")
        try:
            self.packets = sniff(count=count, filter=filter_rule)
            logger.info(f"Captured {len(self.packets)} packets")
            return self.packets
        except Exception as e:
            logger.error(f"Error capturing packets: {e}")
            return []
    
    def load_pcap_file(self, filepath):
        """Load packets from PCAP file"""
        try:
            self.packets = rdpcap(filepath)
            logger.info(f"Loaded {len(self.packets)} packets from {filepath}")
            return self.packets
        except Exception as e:
            logger.error(f"Error loading PCAP file: {e}")
            return []
    
    def extract_payloads(self, min_length=10):
        """Extract payload data from packets"""
        self.payloads = []
        for packet in self.packets:
            if packet.haslayer('Raw'):
                payload = bytes(packet['Raw'])
                if len(payload) >= min_length:
                    self.payloads.append(payload)
        
        logger.info(f"Extracted {len(self.payloads)} payloads")
        return self.payloads
    
    def save_data(self, filepath):
        """Save captured data"""
        data = {
            'payloads': [payload.hex() for payload in self.payloads],
            'packet_count': len(self.packets)
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)
        logger.info(f"Data saved to {filepath}")

class PacketPreprocessor:
    """Preprocess packet data for ML models"""
    
    def __init__(self):
        self.vocab_size = 256  # byte values 0-255
        self.max_length = 512
        self.tokenized_data = []
        
    def byte_tokenize(self, payloads: List[bytes]) -> List[List[int]]:
        """Convert bytes to integer sequences"""
        tokenized = []
        for payload in payloads:
            tokens = list(payload)
            tokenized.append(tokens)
        
        self.tokenized_data = tokenized
        logger.info(f"Tokenized {len(tokenized)} payloads")
        return tokenized
    
    def extract_ngrams(self, sequences: List[List[int]], n=2) -> Dict[tuple, int]:
        """Extract n-grams from sequences"""
        ngrams = Counter()
        for sequence in sequences:
            for i in range(len(sequence) - n + 1):
                ngram = tuple(sequence[i:i+n])
                ngrams[ngram] += 1
        
        logger.info(f"Extracted {len(ngrams)} unique {n}-grams")
        return dict(ngrams)
    
    def pad_sequences(self, sequences: List[List[int]], max_length=None) -> np.ndarray:
        """Pad sequences to uniform length"""
        if max_length is None:
            max_length = self.max_length
            
        padded = np.zeros((len(sequences), max_length), dtype=int)
        for i, seq in enumerate(sequences):
            length = min(len(seq), max_length)
            padded[i, :length] = seq[:length]
        
        logger.info(f"Padded {len(sequences)} sequences to length {max_length}")
        return padded
    
    def create_features(self, sequences: List[List[int]]) -> np.ndarray:
        """Create feature vectors from sequences"""
        features = []
        
        for seq in sequences:
            # Statistical features
            feat_vector = [
                len(seq),  # length
                np.mean(seq) if seq else 0,  # mean byte value
                np.std(seq) if len(seq) > 1 else 0,  # std byte value
                len(set(seq)),  # unique bytes
                seq.count(0),  # null bytes
                seq.count(10),  # newlines
                seq.count(32),  # spaces
            ]
            
            # Byte frequency features (top 20 most common bytes)
            byte_counts = Counter(seq)
            for byte_val in range(20):
                feat_vector.append(byte_counts.get(byte_val, 0))
                
            features.append(feat_vector)
        
        return np.array(features)

class LSTMModel(nn.Module):
    """LSTM model for sequence modeling"""
    
    def __init__(self, vocab_size=256, embedding_dim=128, hidden_size=256, num_layers=2, dropout=0.2):
        super(LSTMModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_size, num_layers, 
                           batch_first=True, dropout=dropout, bidirectional=True)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size * 2, vocab_size)  # *2 for bidirectional
        
    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        dropped = self.dropout(lstm_out)
        output = self.fc(dropped)
        return output

class ProtocolAnalyzer:
    """Main class for protocol analysis and grammar discovery"""
    
    def __init__(self):
        self.capture = PacketCapture()
        self.preprocessor = PacketPreprocessor()
        self.model = None
        self.clusters = None
        self.grammar_rules = []
        
    def analyze_traffic(self, data_source, source_type='live'):
        """Complete analysis pipeline"""
        
        # 1. Data Capture
        if source_type == 'live':
            packets = self.capture.capture_live_traffic(count=data_source)
        else:
            packets = self.capture.load_pcap_file(data_source)
            
        if not packets:
            logger.error("No packets captured")
            return
            
        payloads = self.capture.extract_payloads()
        if not payloads:
            logger.error("No payloads extracted")
            return
            
        # 2. Preprocessing
        tokenized = self.preprocessor.byte_tokenize(payloads)
        features = self.preprocessor.create_features(tokenized)
        padded_sequences = self.preprocessor.pad_sequences(tokenized)
        
        # 3. Clustering
        self.perform_clustering(features)
        
        # 4. Pattern Mining
        patterns = self.mine_patterns(tokenized)
        
        # 5. Grammar Induction
        self.induce_grammar(patterns)
        
        # 6. Visualization
        self.visualize_results(features, patterns)
        
        return {
            'packets_count': len(packets),
            'payloads_count': len(payloads),
            'clusters': self.clusters,
            'patterns': patterns,
            'grammar_rules': self.grammar_rules
        }
    
    def perform_clustering(self, features):
        """Cluster packets into message types"""
        # Normalize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Apply PCA for dimensionality reduction
        pca = PCA(n_components=min(10, features_scaled.shape[1]))
        features_pca = pca.fit_transform(features_scaled)
        
        # K-means clustering
        kmeans = KMeans(n_clusters=5, random_state=42)
        labels = kmeans.fit_predict(features_pca)
        
        # DBSCAN for comparison
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        dbscan_labels = dbscan.fit_predict(features_pca)
        
        self.clusters = {
            'kmeans_labels': labels,
            'dbscan_labels': dbscan_labels,
            'features_pca': features_pca,
            'cluster_centers': kmeans.cluster_centers_
        }
        
        logger.info(f"K-means found {len(np.unique(labels))} clusters")
        logger.info(f"DBSCAN found {len(np.unique(dbscan_labels))} clusters")
        
    def mine_patterns(self, sequences):
        """Mine common patterns from sequences"""
        patterns = {}
        
        # Extract n-grams
        for n in [2, 3, 4]:
            ngrams = self.preprocessor.extract_ngrams(sequences, n)
            # Keep only frequent patterns
            frequent_ngrams = {k: v for k, v in ngrams.items() if v >= 3}
            patterns[f'{n}_grams'] = frequent_ngrams
        
        # Find common subsequences
        common_subseqs = self.find_common_subsequences(sequences)
        patterns['common_subsequences'] = common_subseqs
        
        # Detect protocol keywords (common ASCII patterns)
        keywords = self.detect_keywords(sequences)
        patterns['keywords'] = keywords
        
        return patterns
    
    def find_common_subsequences(self, sequences, min_length=3, min_freq=3):
        """Find common subsequences across packets"""
        subseq_counts = defaultdict(int)
        
        for seq in sequences[:100]:  # Limit for performance
            for i in range(len(seq)):
                for j in range(i + min_length, min(i + 20, len(seq) + 1)):
                    subseq = tuple(seq[i:j])
                    subseq_counts[subseq] += 1
        
        return {k: v for k, v in subseq_counts.items() if v >= min_freq}
    
    def detect_keywords(self, sequences):
        """Detect ASCII keywords in binary data"""
        keywords = Counter()
        
        for seq in sequences:
            try:
                # Convert to string and find words
                text = bytes(seq).decode('utf-8', errors='ignore')
                words = re.findall(r'[A-Za-z]{3,}', text)
                keywords.update(words)
            except:
                continue
                
        return dict(keywords.most_common(20))
    
    def induce_grammar(self, patterns):
        """Induce grammar rules from patterns"""
        rules = []
        
        # Rule 1: Protocol structure based on keywords
        keywords = patterns.get('keywords', {})
        if 'GET' in keywords or 'POST' in keywords:
            rules.append("HTTP_REQUEST -> METHOD PATH VERSION")
            rules.append("METHOD -> GET | POST | PUT | DELETE")
            
        if 'HTTP' in keywords:
            rules.append("HTTP_MESSAGE -> REQUEST | RESPONSE")
            rules.append("REQUEST -> METHOD PATH VERSION HEADERS BODY")
            
        # Rule 2: Pattern-based rules from n-grams
        common_bigrams = patterns.get('2_grams', {})
        for bigram, count in list(common_bigrams.items())[:5]:
            if count > 10:  # Frequent pattern
                rules.append(f"PATTERN -> BYTE_{bigram[0]} BYTE_{bigram[1]}")
        
        # Rule 3: Structure rules based on clusters
        if self.clusters:
            n_clusters = len(np.unique(self.clusters['kmeans_labels']))
            for i in range(n_clusters):
                rules.append(f"MESSAGE_TYPE_{i} -> HEADER PAYLOAD")
        
        self.grammar_rules = rules
        logger.info(f"Induced {len(rules)} grammar rules")
        
        return rules
    
    def visualize_results(self, features, patterns):
        """Create visualizations of the analysis"""
        
        # 1. Cluster visualization
        if self.clusters is not None:
            plt.figure(figsize=(15, 10))
            
            # K-means clusters
            plt.subplot(2, 3, 1)
            scatter = plt.scatter(self.clusters['features_pca'][:, 0], 
                                self.clusters['features_pca'][:, 1], 
                                c=self.clusters['kmeans_labels'], 
                                cmap='viridis', alpha=0.6)
            plt.title('K-means Clustering')
            plt.xlabel('PCA Component 1')
            plt.ylabel('PCA Component 2')
            plt.colorbar(scatter)
            
            # DBSCAN clusters
            plt.subplot(2, 3, 2)
            scatter = plt.scatter(self.clusters['features_pca'][:, 0], 
                                self.clusters['features_pca'][:, 1], 
                                c=self.clusters['dbscan_labels'], 
                                cmap='plasma', alpha=0.6)
            plt.title('DBSCAN Clustering')
            plt.xlabel('PCA Component 1')
            plt.ylabel('PCA Component 2')
            plt.colorbar(scatter)
            
            # Feature distribution
            plt.subplot(2, 3, 3)
            plt.hist(features[:, 0], bins=30, alpha=0.7)
            plt.title('Payload Length Distribution')
            plt.xlabel('Length')
            plt.ylabel('Frequency')
            
            # Top keywords
            plt.subplot(2, 3, 4)
            keywords = patterns.get('keywords', {})
            if keywords:
                words, counts = zip(*list(keywords.items())[:10])
                plt.bar(words, counts)
                plt.title('Top Protocol Keywords')
                plt.xticks(rotation=45)
            
            # N-gram frequency
            plt.subplot(2, 3, 5)
            bigrams = patterns.get('2_grams', {})
            if bigrams:
                top_bigrams = list(bigrams.values())[:20]
                plt.hist(top_bigrams, bins=15)
                plt.title('Bigram Frequency Distribution')
                plt.xlabel('Frequency')
                plt.ylabel('Count')
            
            # Cluster size distribution
            plt.subplot(2, 3, 6)
            cluster_sizes = np.bincount(self.clusters['kmeans_labels'])
            plt.bar(range(len(cluster_sizes)), cluster_sizes)
            plt.title('Cluster Size Distribution')
            plt.xlabel('Cluster ID')
            plt.ylabel('Number of Packets')
            
            plt.tight_layout()
            plt.show()
    
    def export_results(self, filepath):
        """Export analysis results"""
        results = {
            'grammar_rules': self.grammar_rules,
            'clusters': {
                'kmeans_labels': self.clusters['kmeans_labels'].tolist() if self.clusters else [],
                'n_clusters': len(np.unique(self.clusters['kmeans_labels'])) if self.clusters else 0
            },
            'model_info': {
                'vocab_size': self.preprocessor.vocab_size,
                'max_length': self.preprocessor.max_length
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Results exported to {filepath}")

def main():
    """Main execution function"""
    analyzer = ProtocolAnalyzer()
    
    # Example usage
    print("🛰️ FlowParse - Network Protocol Grammar Discovery")
    print("=" * 50)
    
    # Option 1: Capture live traffic
    # results = analyzer.analyze_traffic(500, 'live')
    
    # Option 2: Load from PCAP file
    # results = analyzer.analyze_traffic('capture.pcap', 'file')
    
    # For demonstration, let's create some synthetic data
    print("Creating synthetic network traffic data for demonstration...")
    
    # Simulate HTTP-like traffic
    synthetic_payloads = [
        b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
        b'POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"key":"value"}',
        b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>',
        b'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found',
        b'GET /favicon.ico HTTP/1.1\r\nHost: example.com\r\n\r\n',
        b'POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=123',
    ] * 20  # Multiply to have more samples
    
    # Inject synthetic data
    analyzer.capture.payloads = synthetic_payloads
    
    # Run preprocessing and analysis
    tokenized = analyzer.preprocessor.byte_tokenize(synthetic_payloads)
    features = analyzer.preprocessor.create_features(tokenized)
    
    # Perform clustering
    analyzer.perform_clustering(features)
    
    # Mine patterns
    patterns = analyzer.mine_patterns(tokenized)
    
    # Induce grammar
    grammar = analyzer.induce_grammar(patterns)
    
    # Display results
    print("\n📊 Analysis Results:")
    print(f"✓ Processed {len(synthetic_payloads)} payloads")
    print(f"✓ Found {len(np.unique(analyzer.clusters['kmeans_labels']))} message clusters")
    print(f"✓ Discovered {len(patterns.get('keywords', {}))} protocol keywords")
    print(f"✓ Induced {len(grammar)} grammar rules")
    
    print("\n📝 Sample Grammar Rules:")
    for rule in grammar[:5]:
        print(f"  • {rule}")
    
    print("\n🔍 Top Keywords Found:")
    for keyword, count in list(patterns.get('keywords', {}).items())[:5]:
        print(f"  • {keyword}: {count} occurrences")
    
    # Export results
    analyzer.export_results('flowparse_results.json')
    
    print("\n✅ Analysis complete! Results exported to 'flowparse_results.json'")
    print("\n📈 Visualization will be displayed...")
    
    # Show visualization
    analyzer.visualize_results(features, patterns)

if __name__ == "__main__":
    main()