import React, { useState } from 'react';
import { X, Play, Loader, CheckCircle, XCircle } from 'lucide-react';
import { deploymentApi } from '@/services/api';
import { DeploymentResult } from '@/types';
import Button from './Button';

interface DeploymentModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const DeploymentModal: React.FC<DeploymentModalProps> = ({ isOpen, onClose }) => {
  const [ipsInput, setIpsInput] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isDeploying, setIsDeploying] = useState(false);
  const [results, setResults] = useState<DeploymentResult[]>([]);

  if (!isOpen) return null;

  const handleDeploy = async () => {
    const ips = ipsInput.split(',').map(ip => ip.trim()).filter(Boolean);
    if (ips.length === 0 || !username || !password) return;

    setIsDeploying(true);
    setResults(ips.map(ip => ({ ip, status: 'pending' })));

    try {
      const res = await deploymentApi.pushDeploy({
        ips,
        admin_username: username,
        admin_password: password
      });
      setResults(res);
    } catch (error) {
      console.error(error);
      setResults(ips.map(ip => ({ ip, status: 'failed', message: 'Network or server error' })));
    } finally {
      setIsDeploying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="glass-card w-full max-w-2xl p-6 relative">
        <button onClick={onClose} className="absolute right-4 top-4 text-white/50 hover:text-white transition-colors">
          <X className="w-5 h-5" />
        </button>
        
        <h2 className="text-xl font-semibold text-white mb-6">Deploy Endpoint Agents</h2>
        
        <div className="space-y-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-white/70 mb-1">Target IPs (comma separated)</label>
            <input 
              type="text" 
              value={ipsInput} 
              onChange={e => setIpsInput(e.target.value)} 
              className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-amber-500/50"
              placeholder="192.168.1.10, 192.168.1.11"
              disabled={isDeploying}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-white/70 mb-1">Admin Username</label>
              <input 
                type="text" 
                value={username} 
                onChange={e => setUsername(e.target.value)} 
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-amber-500/50"
                placeholder="Administrator"
                disabled={isDeploying}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-white/70 mb-1">Admin Password</label>
              <input 
                type="password" 
                value={password} 
                onChange={e => setPassword(e.target.value)} 
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-amber-500/50"
                disabled={isDeploying}
              />
            </div>
          </div>
        </div>

        {results.length > 0 && (
          <div className="bg-black/30 rounded-lg p-4 mb-6 max-h-48 overflow-y-auto">
            <h3 className="text-sm font-medium text-white/70 mb-3">Deployment Status</h3>
            <div className="space-y-2">
              {results.map((res, i) => (
                <div key={i} className="flex items-center justify-between text-sm">
                  <span className="text-white">{res.ip}</span>
                  <div className="flex items-center gap-2">
                    {res.status === 'pending' && <><Loader className="w-4 h-4 text-amber-500 animate-spin"/> <span className="text-amber-500">Deploying...</span></>}
                    {res.status === 'success' && <><CheckCircle className="w-4 h-4 text-emerald-400"/> <span className="text-emerald-400">Success</span></>}
                    {res.status === 'failed' && <><XCircle className="w-4 h-4 text-rose-400"/> <span className="text-rose-400" title={res.message}>Failed</span></>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex justify-end gap-3">
          <Button variant="outline" onClick={onClose} disabled={isDeploying}>Cancel</Button>
          <Button onClick={handleDeploy} disabled={isDeploying || !ipsInput || !username || !password} icon={isDeploying ? undefined : <Play className="w-4 h-4" />}>
            {isDeploying ? 'Deploying...' : 'Start Deployment'}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default DeploymentModal;
