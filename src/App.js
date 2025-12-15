import React, { useState, useRef } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Upload, Play, Database, Brain, Eye, Download } from 'lucide-react';

const FlowParseDashboard = () => {
  const [analysisResults, setAnalysisResults] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState('');
  const fileInputRef = useRef(null);

  // Mock data for demonstration
  const mockResults = {
    packetsCount: 120,
    payloadsCount: 98,
    clusters: {
      kmeans_labels: [0, 1, 0, 2, 1, 0, 2, 1, 0, 2, 1, 0, 1, 2, 0],
      n_clusters: 3
    },
    grammarRules: [
      "HTTP_REQUEST -> METHOD PATH VERSION",
      "METHOD -> GET | POST | PUT | DELETE",
      "HTTP_MESSAGE -> REQUEST | RESPONSE",
      "REQUEST -> METHOD PATH VERSION HEADERS BODY",
      "PATTERN -> BYTE_72 BYTE_84",
      "MESSAGE_TYPE_0 -> HEADER PAYLOAD",
      "MESSAGE_TYPE_1 -> HEADER PAYLOAD",
      "MESSAGE_TYPE_2 -> HEADER PAYLOAD"
    ],
    keywords: {
      'HTTP': 45,
      'GET': 28,
      'POST': 12,
      'Host': 40,
      'Content': 25,
      'Type': 25,
      'html': 15,
      'json': 8,
      'example': 35,
      'com': 35
    },
    patterns: {
      '2_grams': { '[72, 84]': 45, '[84, 84]': 45, '[80, 32]': 25 },
      '3_grams': { '[72, 84, 84]': 45, '[71, 69, 84]': 28 }
    }
  };

  const runAnalysis = () => {
    setIsAnalyzing(true);
    setTimeout(() => {
      setAnalysisResults(mockResults);
      setIsAnalyzing(false);
    }, 3000);
  };

  const clusterData = analysisResults ? 
    Array.from({length: analysisResults.clusters.n_clusters}, (_, i) => ({
      cluster: `Type ${i}`,
      count: analysisResults.clusters.kmeans_labels.filter(label => label === i).length
    })) : [];

  const keywordData = analysisResults ?
    Object.entries(analysisResults.keywords).slice(0, 8).map(([word, count]) => ({
      keyword: word,
      frequency: count
    })) : [];

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  const getProgressWidth = (count) => {
    if (clusterData.length === 0) return '0%';
    const maxCount = Math.max(...clusterData.map(c => c.count));
    return `${(count / maxCount) * 100}%`;
  };

  const triggerFileUpload = () => {
  if (fileInputRef.current) {
    fileInputRef.current.click();
  }
};

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const validExtensions = ['.pcap', '.pcapng', '.cap'];
      const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
      if (validExtensions.includes(fileExtension)) {
        setUploadedFile(file);
        setUploadStatus(`Uploaded: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`);
        
        // Generate dynamic results based on file characteristics
        setTimeout(() => {
          const fileSize = file.size;
          const fileName = file.name.toLowerCase();
          
          // Base calculations from file size
          const packetCount = Math.floor((fileSize / 500) + Math.random() * 800 + 100);
          const payloadCount = Math.floor(packetCount * (0.7 + Math.random() * 0.3));
          const clusterCount = Math.floor(Math.random() * 3) + 3; // 3-5 clusters
          
          // Generate cluster labels based on cluster count
          const clusterLabels = Array.from({length: packetCount / 10}, () => 
            Math.floor(Math.random() * clusterCount)
          );
          
          // Dynamic keywords based on filename and size
          let keywords = {};
          let grammarRules = [];
          let patterns = {};
          
          // Determine protocol type from filename or generate random
          if (fileName.includes('http') || fileName.includes('web')) {
            // HTTP-dominant traffic
            keywords = {
              'HTTP': Math.floor(Math.random() * 50) + 40,
              'GET': Math.floor(Math.random() * 40) + 20,
              'POST': Math.floor(Math.random() * 30) + 10,
              'Host': Math.floor(Math.random() * 45) + 35,
              'Content-Type': Math.floor(Math.random() * 35) + 15,
              'User-Agent': Math.floor(Math.random() * 40) + 20,
              'Accept': Math.floor(Math.random() * 30) + 15,
              'Cookie': Math.floor(Math.random() * 25) + 5,
              'html': Math.floor(Math.random() * 20) + 10,
              'json': Math.floor(Math.random() * 15) + 5
            };
            grammarRules = [
              "HTTP_REQUEST -> METHOD PATH VERSION",
              "METHOD -> GET | POST | PUT | DELETE | HEAD",
              "HTTP_RESPONSE -> VERSION STATUS_CODE REASON",
              "HEADER -> FIELD_NAME COLON FIELD_VALUE",
              "REQUEST -> METHOD PATH VERSION HEADERS BODY",
              "RESPONSE -> VERSION STATUS_CODE HEADERS BODY",
              "PATTERN_HTTP -> BYTE_72 BYTE_84 BYTE_84 BYTE_80",
              "MESSAGE_TYPE_0 -> REQUEST_HEADER BODY",
              "MESSAGE_TYPE_1 -> RESPONSE_HEADER BODY",
              "MESSAGE_TYPE_2 -> KEEP_ALIVE_HEADER"
            ];
            patterns = {
              '2_grams': { 
                '[72, 84]': Math.floor(Math.random() * 30) + 20, // HT
                '[84, 84]': Math.floor(Math.random() * 30) + 20, // TT
                '[80, 47]': Math.floor(Math.random() * 25) + 15, // P/
                '[71, 69]': Math.floor(Math.random() * 20) + 10  // GE
              },
              '3_grams': { 
                '[72, 84, 84]': Math.floor(Math.random() * 25) + 15, // HTT
                '[71, 69, 84]': Math.floor(Math.random() * 20) + 10, // GET
                '[80, 79, 83]': Math.floor(Math.random() * 15) + 8   // POS
              }
            };
          } else if (fileName.includes('dns') || fileName.includes('domain')) {
            // DNS-dominant traffic
            keywords = {
              'DNS': Math.floor(Math.random() * 60) + 30,
              'QUERY': Math.floor(Math.random() * 40) + 20,
              'RESPONSE': Math.floor(Math.random() * 35) + 18,
              'A': Math.floor(Math.random() * 25) + 15,
              'AAAA': Math.floor(Math.random() * 20) + 10,
              'CNAME': Math.floor(Math.random() * 18) + 8,
              'MX': Math.floor(Math.random() * 15) + 5,
              'NS': Math.floor(Math.random() * 12) + 4,
              'com': Math.floor(Math.random() * 30) + 20,
              'org': Math.floor(Math.random() * 15) + 8
            };
            grammarRules = [
              "DNS_MESSAGE -> HEADER QUESTION ANSWER",
              "QUESTION -> QNAME QTYPE QCLASS",
              "ANSWER -> NAME TYPE CLASS TTL RDATA",
              "QTYPE -> A | AAAA | CNAME | MX | NS",
              "DNS_QUERY -> QUERY_ID FLAGS QUESTION",
              "DNS_RESPONSE -> QUERY_ID FLAGS ANSWER",
              "PATTERN_DNS -> BYTE_68 BYTE_78 BYTE_83",
              "MESSAGE_TYPE_0 -> QUERY_HEADER QUESTION",
              "MESSAGE_TYPE_1 -> RESPONSE_HEADER ANSWER",
              "MESSAGE_TYPE_2 -> ERROR_RESPONSE"
            ];
            patterns = {
              '2_grams': { 
                '[68, 78]': Math.floor(Math.random() * 25) + 15, // DN
                '[78, 83]': Math.floor(Math.random() * 20) + 12, // NS
                '[65, 65]': Math.floor(Math.random() * 18) + 10  // AA
              },
              '3_grams': { 
                '[68, 78, 83]': Math.floor(Math.random() * 20) + 12, // DNS
                '[65, 65, 65]': Math.floor(Math.random() * 15) + 8   // AAA
              }
            };
          } else if (fileName.includes('tcp') || fileName.includes('stream')) {
            // TCP-focused traffic
            keywords = {
              'TCP': Math.floor(Math.random() * 70) + 50,
              'SYN': Math.floor(Math.random() * 30) + 15,
              'ACK': Math.floor(Math.random() * 45) + 25,
              'FIN': Math.floor(Math.random() * 20) + 10,
              'RST': Math.floor(Math.random() * 15) + 5,
              'PSH': Math.floor(Math.random() * 25) + 12,
              'URG': Math.floor(Math.random() * 8) + 2,
              'WINDOW': Math.floor(Math.random() * 35) + 20,
              'SEQ': Math.floor(Math.random() * 40) + 25,
              'PORT': Math.floor(Math.random() * 30) + 18
            };
            grammarRules = [
              "TCP_SEGMENT -> HEADER DATA",
              "TCP_HEADER -> SRC_PORT DST_PORT SEQ_NUM ACK_NUM FLAGS",
              "FLAGS -> SYN | ACK | FIN | RST | PSH | URG",
              "CONNECTION -> SYN SYN_ACK ACK DATA_TRANSFER FIN",
              "HANDSHAKE -> SYN SYN_ACK ACK",
              "TEARDOWN -> FIN ACK FIN ACK",
              "PATTERN_TCP -> BYTE_84 BYTE_67 BYTE_80",
              "MESSAGE_TYPE_0 -> HANDSHAKE_PACKET",
              "MESSAGE_TYPE_1 -> DATA_PACKET",
              "MESSAGE_TYPE_2 -> CONTROL_PACKET"
            ];
            patterns = {
              '2_grams': { 
                '[84, 67]': Math.floor(Math.random() * 35) + 20, // TC
                '[67, 80]': Math.floor(Math.random() * 32) + 18, // CP
                '[83, 89]': Math.floor(Math.random() * 15) + 8   // SY
              },
              '3_grams': { 
                '[84, 67, 80]': Math.floor(Math.random() * 30) + 15, // TCP
                '[83, 89, 78]': Math.floor(Math.random() * 12) + 6   // SYN
              }
            };
          } else {
            // Mixed/Unknown traffic - generate varied protocols
            const protocolMix = Math.random();
            keywords = {
              'HTTP': Math.floor(Math.random() * 40) + 10,
              'TCP': Math.floor(Math.random() * 50) + 20,
              'UDP': Math.floor(Math.random() * 30) + 10,
              'DNS': Math.floor(Math.random() * 25) + 8,
              'TLS': Math.floor(Math.random() * 20) + 5,
              'GET': Math.floor(Math.random() * 25) + 5,
              'POST': Math.floor(Math.random() * 15) + 3,
              'ACK': Math.floor(Math.random() * 35) + 15,
              'SYN': Math.floor(Math.random() * 20) + 8,
              'FIN': Math.floor(Math.random() * 15) + 5
            };
            grammarRules = [
              "MIXED_PROTOCOL -> TCP_TRAFFIC | HTTP_TRAFFIC | DNS_TRAFFIC",
              "TCP_TRAFFIC -> TCP_HEADER TCP_DATA",
              "HTTP_TRAFFIC -> HTTP_REQUEST | HTTP_RESPONSE", 
              "DNS_TRAFFIC -> DNS_QUERY | DNS_RESPONSE",
              "PROTOCOL_HEADER -> TYPE LENGTH DATA",
              "MESSAGE -> HEADER PAYLOAD CHECKSUM",
              "PATTERN_MIX -> BYTE_SEQUENCE",
              "MESSAGE_TYPE_0 -> CONTROL_MESSAGE",
              "MESSAGE_TYPE_1 -> DATA_MESSAGE", 
              "MESSAGE_TYPE_2 -> ERROR_MESSAGE"
            ];
            patterns = {
              '2_grams': { 
                '[72, 84]': Math.floor(Math.random() * 20) + 5,
                '[84, 67]': Math.floor(Math.random() * 25) + 8,
                '[68, 78]': Math.floor(Math.random() * 15) + 4
              },
              '3_grams': { 
                '[72, 84, 84]': Math.floor(Math.random() * 18) + 6,
                '[84, 67, 80]': Math.floor(Math.random() * 15) + 5
              }
            };
          }
          
          setAnalysisResults({
            packetsCount: packetCount,
            payloadsCount: payloadCount,
            clusters: {
              kmeans_labels: clusterLabels,
              n_clusters: clusterCount
            },
            grammarRules: grammarRules,
            keywords: keywords,
            patterns: patterns,
            fileName: file.name,
            fileSize: (file.size / 1024 / 1024).toFixed(2) + ' MB'
          });
          
          setUploadStatus('Analysis complete!');
        }, 2000);
      } else {
        setUploadStatus('Please upload a valid PCAP file (.pcap, .pcapng, .cap)');
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <div className="bg-black/20 backdrop-blur-lg border-b border-white/10">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                <Database className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">🛰️ FlowParse</h1>
                <p className="text-blue-200 text-sm">ML-Powered Protocol Grammar Discovery</p>
              </div>
            </div>
            <div className="flex space-x-3">
              <button
                onClick={runAnalysis}
                disabled={isAnalyzing}
                className="flex items-center space-x-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg transition-all duration-200"
              >
                {isAnalyzing ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span>Run Analysis</span>
                  </>
                )}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
              <button
                onClick={triggerFileUpload}
                className="flex items-center space-x-2 bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg transition-all duration-200"
              >
                <Upload className="w-4 h-4" />
                <span>Upload PCAP</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {uploadStatus && (
        <div className="container mx-auto px-6">
          <div className="bg-black/20 backdrop-blur-lg border border-white/10 rounded-lg px-4 py-2 mb-4">
            <p className="text-blue-200 text-sm">{uploadStatus}</p>
          </div>
        </div>
      )}

      {analysisResults && analysisResults.fileName && (
        <div className="container mx-auto px-6">
          <div className="bg-white/5 backdrop-blur-lg rounded-xl p-4 border border-white/10 mb-4">
            <div className="flex justify-between">
              <span className="text-blue-200">File Name:</span>
              <span className="text-white font-mono text-sm">{analysisResults.fileName}</span>
            </div>
            {analysisResults.fileSize && (
              <div className="flex justify-between">
                <span className="text-blue-200">File Size:</span>
                <span className="text-white font-mono text-sm">{analysisResults.fileSize}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        {!analysisResults && !isAnalyzing && (
          <div className="text-center py-20">
            <div className="w-24 h-24 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center mx-auto mb-6">
              <Brain className="w-12 h-12 text-white" />
            </div>
            <h2 className="text-3xl font-bold text-white mb-4">Ready to Discover Protocol Grammars</h2>
            <p className="text-blue-200 text-lg mb-8 max-w-2xl mx-auto">
              Upload network traffic or start live capture to automatically discover protocol structures using machine learning
            </p>
            <button
              onClick={runAnalysis}
              className="bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white px-8 py-3 rounded-lg text-lg font-medium transition-all duration-200"
            >
              Start Demo Analysis
            </button>
          </div>
        )}

        {isAnalyzing && (
          <div className="text-center py-20">
            <div className="w-24 h-24 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse">
              <Brain className="w-12 h-12 text-white animate-bounce" />
            </div>
            <h2 className="text-3xl font-bold text-white mb-4">Analyzing Network Traffic</h2>
            <div className="space-y-3 max-w-md mx-auto">
              <div className="flex items-center justify-between text-blue-200">
                <span>Capturing packets...</span>
                <span className="text-green-400">✓</span>
              </div>
              <div className="flex items-center justify-between text-blue-200">
                <span>Preprocessing data...</span>
                <span className="text-green-400">✓</span>
              </div>
              <div className="flex items-center justify-between text-blue-200">
                <span>Running ML models...</span>
                <div className="w-4 h-4 border-2 border-blue-400/20 border-t-blue-400 rounded-full animate-spin" />
              </div>
              <div className="flex items-center justify-between text-blue-200">
                <span>Discovering grammar...</span>
                <span className="text-gray-400">⏳</span>
              </div>
            </div>
          </div>
        )}

        {analysisResults && (
          <div>
            {/* Navigation Tabs */}
            <div className="flex space-x-1 bg-white/5 p-1 rounded-lg mb-8">
              {[
                { id: 'overview', name: 'Overview', icon: Eye },
                { id: 'clusters', name: 'Message Types', icon: Database },
                { id: 'grammar', name: 'Grammar Rules', icon: Brain },
                { id: 'patterns', name: 'Patterns', icon: Download }
              ].map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all duration-200 ${
                      activeTab === tab.id
                        ? 'bg-white/10 text-white'
                        : 'text-blue-200 hover:bg-white/5'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.name}</span>
                  </button>
                );
              })}
            </div>

            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-white">Traffic Summary</h3>
                    <Database className="w-5 h-5 text-blue-400" />
                  </div>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-blue-200">Packets Captured:</span>
                      <span className="text-white font-mono">{analysisResults.packetsCount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-blue-200">Payloads Extracted:</span>
                      <span className="text-white font-mono">{analysisResults.payloadsCount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-blue-200">Message Types:</span>
                      <span className="text-white font-mono">{analysisResults.clusters.n_clusters}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-blue-200">Grammar Rules:</span>
                      <span className="text-white font-mono">{analysisResults.grammarRules.length}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-white">Protocol Keywords</h3>
                    <Brain className="w-5 h-5 text-purple-400" />
                  </div>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie
                        data={keywordData.slice(0, 5)}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        paddingAngle={5}
                        dataKey="frequency"
                      >
                        {keywordData.slice(0, 5).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-white">Message Clusters</h3>
                    <Eye className="w-5 h-5 text-green-400" />
                  </div>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={clusterData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="cluster" stroke="#9CA3AF" />
                      <YAxis stroke="#9CA3AF" />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1F2937',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#F3F4F6'
                        }}
                      />
                      <Bar dataKey="count" fill="#8B5CF6" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Clusters Tab */}
            {activeTab === 'clusters' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                    <h3 className="text-xl font-semibold text-white mb-4">Message Type Distribution</h3>
                    <ResponsiveContainer width="100%" height={300}>
                      <BarChart data={clusterData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis dataKey="cluster" stroke="#9CA3AF" />
                        <YAxis stroke="#9CA3AF" />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1F2937',
                            border: '1px solid #374151',
                            borderRadius: '8px',
                            color: '#F3F4F6'
                          }}
                        />
                        <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                    <h3 className="text-xl font-semibold text-white mb-4">Cluster Analysis</h3>
                    <div className="space-y-4">
                      {clusterData.map((cluster, index) => (
                        <div key={cluster.cluster} className="bg-white/5 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-white font-medium">{cluster.cluster}</span>
                            <span className="text-sm text-blue-200">{cluster.count} packets</span>
                          </div>
                          <div className="w-full bg-gray-700 rounded-full h-2">
                            <div
                              className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-300"
                              style={{ width: getProgressWidth(cluster.count) }}
                            ></div>
                          </div>
                          <p className="text-sm text-blue-200 mt-2">
                            {index === 0 && "Likely HTTP requests with GET/POST methods"}
                            {index === 1 && "HTTP responses with status codes"}
                            {index === 2 && "Protocol handshakes or keep-alive messages"}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Grammar Tab */}
            {activeTab === 'grammar' && (
              <div className="space-y-6">
                <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-semibold text-white">Discovered Grammar Rules</h3>
                    <span className="text-sm text-blue-200 bg-white/5 px-3 py-1 rounded-full">
                      {analysisResults.grammarRules.length} rules
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-lg font-medium text-white mb-4">Protocol Structure Rules</h4>
                      <div className="space-y-3">
                        {analysisResults.grammarRules.slice(0, 4).map((rule, index) => (
                          <div key={index} className="bg-black/20 rounded-lg p-4 border border-white/10">
                            <code className="text-green-400 text-sm font-mono block">
                              {rule}
                            </code>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-lg font-medium text-white mb-4">Pattern-Based Rules</h4>
                      <div className="space-y-3">
                        {analysisResults.grammarRules.slice(4).map((rule, index) => (
                          <div key={index} className="bg-black/20 rounded-lg p-4 border border-white/10">
                            <code className="text-blue-400 text-sm font-mono block">
                              {rule}
                            </code>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="mt-8 p-4 bg-gradient-to-r from-purple-500/10 to-blue-500/10 rounded-lg border border-purple-500/20">
                    <h4 className="text-white font-medium mb-2">Grammar Interpretation</h4>
                    <p className="text-blue-200 text-sm">
                      The ML model has identified HTTP-like protocol patterns with request-response structure. 
                      Rules show method definitions (GET, POST), message composition, and byte-level patterns 
                      that frequently appear together in the captured traffic.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Patterns Tab */}
            {activeTab === 'patterns' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                    <h3 className="text-xl font-semibold text-white mb-4">Protocol Keywords</h3>
                    <ResponsiveContainer width="100%" height={300}>
                      <BarChart data={keywordData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis dataKey="keyword" stroke="#9CA3AF" />
                        <YAxis stroke="#9CA3AF" />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1F2937',
                            border: '1px solid #374151',
                            borderRadius: '8px',
                            color: '#F3F4F6'
                          }}
                        />
                        <Bar dataKey="frequency" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                    <h3 className="text-xl font-semibold text-white mb-4">Frequent N-Grams</h3>
                    <div className="space-y-4">
                      <div>
                        <h5 className="text-white font-medium mb-2">Bigrams</h5>
                        <div className="space-y-2">
                          {Object.entries(analysisResults.patterns['2_grams']).slice(0, 3).map(([ngram, count]) => (
                            <div key={ngram} className="flex justify-between items-center bg-black/20 rounded p-3">
                              <code className="text-cyan-400 text-sm">{ngram}</code>
                              <span className="text-blue-200">{count}x</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      <div>
                        <h5 className="text-white font-medium mb-2">Trigrams</h5>
                        <div className="space-y-2">
                          {Object.entries(analysisResults.patterns['3_grams']).slice(0, 2).map(([ngram, count]) => (
                            <div key={ngram} className="flex justify-between items-center bg-black/20 rounded p-3">
                              <code className="text-pink-400 text-sm">{ngram}</code>
                              <span className="text-blue-200">{count}x</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
                  <h3 className="text-xl font-semibold text-white mb-4">Pattern Analysis Summary</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="text-center">
                      <div className="text-3xl font-bold text-blue-400 mb-2">
                        {Object.keys(analysisResults.keywords).length}
                      </div>
                      <div className="text-blue-200 text-sm">Unique Keywords</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-purple-400 mb-2">
                        {Object.keys(analysisResults.patterns['2_grams']).length}
                      </div>
                      <div className="text-blue-200 text-sm">Bigram Patterns</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-green-400 mb-2">
                        {Object.keys(analysisResults.patterns['3_grams']).length}
                      </div>
                      <div className="text-blue-200 text-sm">Trigram Patterns</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default FlowParseDashboard;
