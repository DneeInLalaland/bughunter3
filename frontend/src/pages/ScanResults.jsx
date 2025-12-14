import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Download, Filter, AlertTriangle, TrendingUp } from 'lucide-react';
import VulnerabilityTable from '../components/vulnerabilities/VulnerabilityTable';
import NetworkGraph from '../components/vulnerabilities/NetworkGraph';
import LoadingSpinner from '../components/common/LoadingSpinner';
import Button from '../components/common/Button';
import { scanAPI } from '../services/api';
import toast from 'react-hot-toast';

const ScanResults = () => {
  const { scanId } = useParams();
  const [loading, setLoading] = useState(true);
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filteredVulnerabilities, setFilteredVulnerabilities] = useState([]);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [showGraph, setShowGraph] = useState(false);

  useEffect(() => {
    fetchScanResults();
  }, [scanId]);

  useEffect(() => {
    filterVulnerabilities();
  }, [selectedSeverity, vulnerabilities]);

  const fetchScanResults = async () => {
    try {
      setLoading(true);
      const scanData = await scanAPI.getScan(scanId);
      console.log('Scan data:', scanData);
      setScan(scanData);
      
      // vulnerabilities มาพร้อมกับ scanData แล้ว
      if (scanData.vulnerabilities) {
        setVulnerabilities(scanData.vulnerabilities);
      }
    } catch (error) {
      console.error('Error fetching scan results:', error);
      toast.error('Failed to load scan results');
    } finally {
      setLoading(false);
    }
  };

  const filterVulnerabilities = () => {
    if (selectedSeverity === 'all') {
      setFilteredVulnerabilities(vulnerabilities);
    } else {
      setFilteredVulnerabilities(
        vulnerabilities.filter(v => v.severity === selectedSeverity)
      );
    }
  };

  const handleDownloadReport = async () => {
    try {
      await scanAPI.downloadReport(scanId);
      toast.success('Report downloaded successfully!');
    } catch (error) {
      console.error('Error downloading report:', error);
      toast.error('Failed to download report');
    }
  };

  // คำนวณจำนวนแต่ละ severity
  const getSeverityCounts = () => {
    const counts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0
    };
    
    vulnerabilities.forEach(v => {
      const severity = v.severity || 'Low';
      if (counts[severity] !== undefined) {
        counts[severity]++;
      }
    });
    
    return counts;
  };

  const severityCounts = getSeverityCounts();

  if (loading) {
    return <LoadingSpinner size="lg" text="Loading results..." />;
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <p className="text-gray-500">Scan not found</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link to="/scans">
            <Button variant="outline" icon={ArrowLeft}>
              Back
            </Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Scan Results</h1>
            <p className="mt-1 text-gray-600">{scan.target_url}</p>
          </div>
        </div>
        <Button onClick={handleDownloadReport} icon={Download}>
          Download Report
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
          <p className="text-sm text-gray-600">Total Vulnerabilities</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">
            {scan.total_vulnerabilities || vulnerabilities.length}
          </p>
        </div>
        <div className="bg-red-50 rounded-lg shadow-sm p-6 border border-red-200">
          <p className="text-sm text-red-600">Critical</p>
          <p className="text-3xl font-bold text-red-600 mt-2">
            {severityCounts.Critical}
          </p>
        </div>
        <div className="bg-orange-50 rounded-lg shadow-sm p-6 border border-orange-200">
          <p className="text-sm text-orange-600">High</p>
          <p className="text-3xl font-bold text-orange-600 mt-2">
            {severityCounts.High}
          </p>
        </div>
        <div className="bg-yellow-50 rounded-lg shadow-sm p-6 border border-yellow-200">
          <p className="text-sm text-yellow-600">Medium</p>
          <p className="text-3xl font-bold text-yellow-600 mt-2">
            {severityCounts.Medium}
          </p>
        </div>
      </div>

      {/* Filters & Graph Toggle */}
      <div className="flex items-center justify-between bg-white rounded-lg shadow-sm p-4 border border-gray-200">
        <div className="flex items-center space-x-4">
          <Filter className="h-5 w-5 text-gray-600" />
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="border-gray-300 rounded-lg focus:ring-primary-500 focus:border-primary-500"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
          <span className="text-sm text-gray-600">
            Showing {filteredVulnerabilities.length} vulnerabilities
          </span>
        </div>
        <Button
          variant="outline"
          icon={TrendingUp}
          onClick={() => setShowGraph(!showGraph)}
        >
          {showGraph ? 'Hide' : 'Show'} Network Graph
        </Button>
      </div>

      {/* Network Graph */}
      {showGraph && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Attack Surface Map</h2>
          <NetworkGraph vulnerabilities={filteredVulnerabilities} />
        </div>
      )}

      {/* Vulnerabilities Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900">Vulnerabilities Found</h2>
        </div>
        <VulnerabilityTable vulnerabilities={filteredVulnerabilities} />
      </div>
    </div>
  );
};

export default ScanResults;
