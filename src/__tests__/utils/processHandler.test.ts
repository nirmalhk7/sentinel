import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleProcess } from '../../utils/processHandler';
import { NextApiResponse } from 'next';

import { spawn } from 'child_process';

vi.mock('child_process', () => {
  const spawnMock = vi.fn();
  return {
    spawn: spawnMock,
    default: { spawn: spawnMock }
  }
});

describe('handleProcess', () => {
  let mockRes: Partial<NextApiResponse>;
  let mockProcess: any;

  beforeEach(() => {
    vi.clearAllMocks();

    mockRes = {
      setHeader: vi.fn(),
      status: vi.fn().mockReturnThis(),
      end: vi.fn(),
      write: vi.fn(),
      json: vi.fn(),
      headersSent: false,
    };

    const EventEmitter = require('events');
    mockProcess = new EventEmitter();
    mockProcess.stdout = new EventEmitter();
    mockProcess.stderr = new EventEmitter();
    mockProcess.kill = vi.fn();

    mockProcess._trigger = mockProcess.emit.bind(mockProcess);
    mockProcess.stdout._trigger = mockProcess.stdout.emit.bind(mockProcess.stdout);
    mockProcess.stderr._trigger = mockProcess.stderr.emit.bind(mockProcess.stderr);

    // Catch unhandled errors so the test doesn't fail when emitting 'error'
    mockProcess.on('error', () => {});

    vi.mocked(spawn).mockImplementation(() => mockProcess as any);
  });

  it('should set Content-Type header', () => {
    handleProcess('test-cmd', ['arg1'], mockRes as NextApiResponse);
    expect(mockRes.setHeader).toHaveBeenCalledWith('Content-Type', 'text/plain;charset=utf-8');
  });

  it('should handle stdout data correctly', () => {
    handleProcess('test-cmd', [], mockRes as NextApiResponse);

    // Simulate stdout data
    mockProcess.stdout._trigger('data', Buffer.from('test output'));

    expect(mockRes.write).toHaveBeenCalledWith('test output');
  });

  it('should handle stderr data correctly', () => {
    handleProcess('test-cmd', [], mockRes as NextApiResponse);

    // Simulate stderr data
    mockProcess.stderr._trigger('data', Buffer.from('test error'));

    expect(mockRes.write).toHaveBeenCalledWith('test error');
  });

  it('should close response on successful process close', () => {
    handleProcess('test-cmd', [], mockRes as NextApiResponse);

    // Simulate successful close
    mockProcess._trigger('close', 0); // exit code 0

    expect(mockRes.end).toHaveBeenCalled();
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  it('should return 500 on process error close', () => {
    handleProcess('test-cmd', [], mockRes as NextApiResponse);

    // Simulate error close
    mockProcess._trigger('close', 1); // exit code 1

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({ error: 'test-cmd process failed', code: 1 });
  });

  it('should handle process start error', () => {
    handleProcess('test-cmd', [], mockRes as NextApiResponse);

    // Simulate process error
    mockProcess._trigger('error', new Error('Start failed'));

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({ error: 'Failed to start process: test-cmd', details: 'Start failed' });
  });

  it('should handle process timeout', () => {
    vi.useFakeTimers();
    handleProcess('test-cmd', [], mockRes as NextApiResponse, 100);

    vi.advanceTimersByTime(150);

    expect(mockProcess.kill).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.end).toHaveBeenCalledWith('Process timed out.');

    vi.useRealTimers();
  });
});
