<?php

namespace LibrasoftFr\SSHConnection;

use InvalidArgumentException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Net\SFTP;
use phpseclib3\Net\SSH2;
use RuntimeException;

/**
 * Class SSHConnection
 * @package librasoft-fr\SSHConnection
 */
class SSHConnection
{
    /**
     *
     */
    const FINGERPRINT_MD5 = 'md5';
    /**
     *
     */
    const FINGERPRINT_SHA1 = 'sha1';
    /**
     * @var SFTP
     */
    protected $sftp;
    /**
     * @var bool
     */
    protected $sftpConnected;

    /**
     * @var
     */
    private $hostname;
    /**
     * @var int
     */
    private $port = 22;
    /**
     * @var
     */
    private $username;
    /**
     * @var
     */
    private $password;
    /**
     * @var
     */
    private $privateKeyPath;
    /**
     * @var
     */
    private $timeout;
    /**
     * @var bool
     */
    private $connected = false;
    /**
     * @var SSH2
     */
    private $ssh;

    /**
     * @param string $hostname
     * @return $this
     */
    public function to(string $hostname): self
    {
        $this->hostname = $hostname;
        return $this;
    }

    /**
     * @param int $port
     * @return $this
     */
    public function onPort(int $port): self
    {
        $this->port = $port;
        return $this;
    }

    /**
     * @param string $username
     * @return $this
     */
    public function as(string $username): self
    {
        $this->username = $username;
        return $this;
    }

    /**
     * @param string $password
     * @return $this
     */
    public function withPassword(string $password): self
    {
        $this->password = $password;
        return $this;
    }

    /**
     * @param string $privateKeyPath
     * @return $this
     */
    public function withPrivateKey(string $privateKeyPath): self
    {
        $this->privateKeyPath = $privateKeyPath;
        return $this;
    }

    /**
     * @param int $timeout
     * @return $this
     */
    public function timeout(int $timeout): self
    {
        $this->timeout = $timeout;
        return $this;
    }

    /**
     *
     */
    private function sanityCheck()
    {
        if (!$this->hostname) {
            throw new InvalidArgumentException('Hostname not specified.');
        }

        if (!$this->username) {
            throw new InvalidArgumentException('Username not specified.');
        }

        if (!$this->password && (!$this->privateKeyPath)) {
            throw new InvalidArgumentException('No password or private key path specified.');
        }
    }

    /**
     * @return $this
     */
    public function connect(): self
    {
        $this->sanityCheck();

        $this->ssh = new SSH2($this->hostname, $this->port, $this->timeout);

        if (!$this->ssh) {
            throw new RuntimeException('Error connecting to server.');
        }


        if ($this->privateKeyPath) {
            $key = PublicKeyLoader::load(file_get_contents($this->privateKeyPath));
            if (!$key instanceof PrivateKey) {
                throw new RuntimeException('Provided key must be private one not public.');
            }
            $authenticated = $this->ssh->login($this->username, $key);
            if (!$authenticated) {
                throw new RuntimeException('Error authenticating with public-private key pair.');
            }
        }

        if ($this->password) {
            $authenticated = $this->ssh->login($this->username, $this->password);
            if (!$authenticated) {
                throw new RuntimeException('Error authenticating with password.');
            }
        }

        if ($this->timeout) {
            $this->ssh->setTimeout($this->timeout);
        }

        $this->connected = true;

        return $this;
    }

    /**
     *
     */
    public function disconnect(): void
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to disconnect. Not yet connected.');
        }

        $this->ssh->disconnect();
    }

    /**
     *
     */
    public function disconnectSftp(): void
    {
        if (!$this->sftpConnected) {
            throw new RuntimeException('Unable to disconnect. Not yet connected.');
        }

        $this->sftp->disconnect();
    }

    /**
     * @return $this
     */
    public function connectSftp(): self
    {
        $this->sanityCheck();

        $this->sftp = new SFTP($this->hostname, $this->port, $this->timeout);

        if (!$this->sftp) {
            throw new RuntimeException('Error connecting to server.');
        }

        if ($this->privateKeyPath) {
            $key = PublicKeyLoader::load(file_get_contents($this->privateKeyPath));
            $authenticated = $this->sftp->login($this->username, $key);
            if (!$authenticated) {
                throw new RuntimeException('Error authenticating with public-private key pair.');
            }
        }

        if ($this->password) {
            $authenticated = $this->sftp->login($this->username, $this->password);
            if (!$authenticated) {
                throw new RuntimeException('Error authenticating with password.');
            }
        }

        if ($this->timeout) {
            $this->sftp->setTimeout($this->timeout);
        }

        $this->sftpConnected = true;

        return $this;
    }

    /**
     * @param string $command
     * @return SSHCommand
     */
    public function run(string $command): SSHCommand
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to run commands when not connected.');
        }

        return new SSHCommand($this->ssh, $command);
    }

    /**
     * @param string $type
     * @return string
     */
    public function fingerprint(string $type = self::FINGERPRINT_MD5)
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to get fingerprint when not connected.');
        }

        $hostKey = substr($this->ssh->getServerPublicHostKey(), 8);

        switch ($type) {
            case self::FINGERPRINT_MD5:
                return strtoupper(md5($hostKey));

            case self::FINGERPRINT_SHA1:
                return strtoupper(sha1($hostKey));
        }

        throw new InvalidArgumentException('Invalid fingerprint type specified.');
    }

    /**
     * @param string $localPath
     * @param string $remotePath
     * @return bool
     */
    public function upload(string $localPath, string $remotePath): bool
    {
        if (!$this->sftpConnected) {
            throw new RuntimeException('Unable to upload file when not connected.');
        }

        if (!file_exists($localPath)) {
            throw new InvalidArgumentException('The local file does not exist.');
        }

        return $this->sftp->put($remotePath, $localPath, \phpseclib3\Net\SFTP::SOURCE_LOCAL_FILE);
    }

    /**
     * @param string $remotePath
     * @param string $localPath
     * @return bool
     */
    public function download(string $remotePath, string $localPath): bool
    {
        if (!$this->sftpConnected) {
            throw new RuntimeException('Unable to download file when not connected.');
        }

        return $this->sftp->get($remotePath, $localPath);
    }

    /**
     * @return bool
     */
    public function isConnected(): bool
    {
        return $this->connected;
    }

    /**
     * @return bool
     */
    public function isSftpConnected(): bool
    {
        return $this->sftpConnected;
    }
}
