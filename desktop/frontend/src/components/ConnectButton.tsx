import { ConnectionStatus } from '../hooks/useClient';

interface ConnectButtonProps {
  status: ConnectionStatus;
  loading: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
}

export function ConnectButton({ status, loading, onConnect, onDisconnect }: ConnectButtonProps) {
  const isConnected = status === 'connected';
  const isConnecting = status === 'connecting' || loading;
  const isError = status === 'error';
  const isOffline = status === 'offline';

  const handleClick = () => {
    if (isConnecting || isOffline) return;
    if (isConnected) {
      onDisconnect();
    } else {
      onConnect();
    }
  };

  const getButtonClasses = () => {
    const base = 'connect-button w-36 h-36 rounded-full flex items-center justify-center transition-all duration-300 focus:outline-none';

    if (isOffline) {
      return `${base} bg-gray-600 cursor-not-allowed opacity-50`;
    }
    if (isConnecting) {
      return `${base} bg-bifrost-warning cursor-wait`;
    }
    if (isConnected) {
      return `${base} connected bg-bifrost-success hover:bg-green-600 cursor-pointer`;
    }
    if (isError) {
      return `${base} error bg-bifrost-error hover:bg-red-600 cursor-pointer`;
    }
    return `${base} bg-bifrost-accent hover:bg-bifrost-accent-hover cursor-pointer`;
  };

  const getIcon = () => {
    if (isConnecting) {
      return (
        <svg className="w-16 h-16 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      );
    }

    if (isConnected) {
      // Power/shield icon for connected state
      return (
        <svg className="w-16 h-16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      );
    }

    // Power icon for disconnected state
    return (
      <svg className="w-16 h-16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9" />
      </svg>
    );
  };

  const getLabel = () => {
    if (isOffline) return 'Offline';
    if (isConnecting) return 'Connecting...';
    if (isConnected) return 'Connected';
    if (isError) return 'Retry';
    return 'Connect';
  };

  return (
    <div className="flex flex-col items-center gap-4">
      <button
        onClick={handleClick}
        disabled={isConnecting || isOffline}
        className={getButtonClasses()}
        aria-label={getLabel()}
      >
        <span className="text-white">{getIcon()}</span>
      </button>
      <span className={`text-lg font-medium ${isConnecting ? 'status-connecting' : ''} ${
        isConnected ? 'text-bifrost-success' :
        isError ? 'text-bifrost-error' :
        isOffline ? 'text-gray-500' :
        'text-bifrost-text-muted'
      }`}>
        {getLabel()}
      </span>
    </div>
  );
}
