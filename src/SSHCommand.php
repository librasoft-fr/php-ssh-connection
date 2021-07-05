<?php

namespace DivineOmega\SSHConnection;

use phpseclib3\Net\SSH2;

/**
 * Class SSHCommand
 * @package DivineOmega\SSHConnection
 */
class SSHCommand
{
    /**
     * @var SSH2
     */
    private $ssh;
    /**
     * @var string
     */
    private $command;
    /**
     * @var
     */
    private $output;
    /**
     * @var
     */
    private $error;

    /**
     * SSHCommand constructor.
     * @param SSH2 $ssh
     * @param string $command
     */
    public function __construct(SSH2 $ssh, string $command)
    {
        $this->ssh = $ssh;
        $this->command = $command;

        $this->execute();
    }

    /**
     *
     */
    private function execute()
    {
        $this->ssh->enableQuietMode();
        $this->output = $this->ssh->exec($this->command);
        $this->error = $this->ssh->getStdError();
    }

    /**
     * @return string
     */
    public function getRawOutput(): string
    {
        return $this->output;
    }

    /**
     * @return string
     */
    public function getRawError(): string
    {
        return $this->error;
    }

    /**
     * @return string
     */
    public function getOutput(): string
    {
        return trim($this->getRawOutput());
    }

    /**
     * @return string
     */
    public function getError(): string
    {
        return trim($this->getRawError());
    }
}
