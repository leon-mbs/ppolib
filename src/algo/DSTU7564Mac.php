<?php

namespace PPOLib\Algo;

/**
 * DSTU 7564 MAC (Kupyna-MAC).
 *
 * Adapted from Bouncy Castle DSTU7564Mac for the PPOLib DSTU7564 engine.
 * The DSTU7564 class must provide updateRaw(), which processes complete
 * blocks without applying the normal hash padding.
 */
class DSTU7564Mac
{
    private $macSize;
    private $blockSize;
    private $engine;
    private $key = null;
    private $paddedKey = null;
    private $invertedKey = null;
    private $buffer = array();
    private $inputLength = 0;

    // ДОБАВЛЕНО: реальный счётчик байт, физически отправленных в $this->engine
    // через updateRaw(). Нужен для корректного вычисления поля длины в
    // финальном блоке (перед invertedKey) — раньше это поле вычислялось
    // пересчётом задним числом и было верным лишь случайно для коротких
    // сообщений (см. объяснение выше).
    private $engineByteCount = 0;

    public function __construct($macBitSize = 256)
    {
        if ($macBitSize !== 256 && $macBitSize !== 384 && $macBitSize !== 512) {
            throw new \InvalidArgumentException('DSTU7564Mac supports only 256, 384 and 512 bit MAC sizes');
        }
        $this->macSize = intdiv($macBitSize, 8);
        $this->blockSize = ($macBitSize > 256) ? 128 : 64;
        $this->engine = new DSTU7564($macBitSize);
    }

    public function getAlgorithmName()
    {
        return 'DSTU7564Mac';
    }

    public function getMacSize()
    {
        return $this->macSize;
    }

    public function init($key)
    {
        $key = $this->toBytes($key);
        if (count($key) === 0) {
            throw new \InvalidArgumentException('DSTU7564Mac key must not be empty');
        }

        $this->key = $key;
        $this->paddedKey = $this->padKey($key);
        $this->invertedKey = array();
        foreach ($key as $byte) {
            $this->invertedKey[] = ((int)$byte ^ 0xFF) & 0xFF;
        }

        $this->buffer = array();
        $this->inputLength = 0;
        $this->newEngine();
        $this->engine->updateRaw($this->paddedKey, 0, count($this->paddedKey));
        // ДОБАВЛЕНО: учитываем paddedKey в физическом счётчике
        $this->engineByteCount = count($this->paddedKey);
        return $this;
    }

    public function update($data)
    {
        $this->ensureInitialised();
        $data = $this->toBytes($data);
        $length = count($data);
        if ($length === 0) {
            return $this;
        }

        $this->inputLength += $length;

        if (count($this->buffer) !== 0) {
            $need = $this->blockSize - count($this->buffer);
            if ($length < $need) {
                $this->buffer = array_merge($this->buffer, $data);
                return $this;
            }
            $this->buffer = array_merge($this->buffer, array_slice($data, 0, $need));
            $this->engine->updateRaw($this->buffer, 0, $this->blockSize);
            // ДОБАВЛЕНО: физически отправили ровно $this->blockSize байт
            $this->engineByteCount += $this->blockSize;
            $this->buffer = array();
            $data = array_slice($data, $need);
            $length -= $need;
        }

        if ($length >= $this->blockSize) {
            $fullLength = $length - ($length % $this->blockSize);
            $this->engine->updateRaw($data, 0, $fullLength);
            // ДОБАВЛЕНО: физически отправили $fullLength байт —
            // именно это число терялось в testOverflow1024Bytes,
            // где буфер оставался пустым, а padMessage() не видел
            // эти байты вообще.
            $this->engineByteCount += $fullLength;
            if ($fullLength !== $length) {
                $this->buffer = array_slice($data, $fullLength);
            }
            return $this;
        }

        $this->buffer = $data;
        return $this;
    }

    public function updateByte($byte)
    {
        $this->ensureInitialised();
        $this->buffer[] = ((int)$byte) & 0xFF;
        $this->inputLength++;
        if (count($this->buffer) === $this->blockSize) {
            $this->engine->updateRaw($this->buffer, 0, $this->blockSize);
            // ДОБАВЛЕНО
            $this->engineByteCount += $this->blockSize;
            $this->buffer = array();
        }
        return $this;
    }

    public function finish()
    {
        $this->ensureInitialised();

        $padded = $this->padMessage($this->buffer, $this->inputLength);
        $this->engine->updateRaw($padded, 0, count($padded));
        // ДОБАВЛЕНО: учитываем весь блок padMessage (хвост буфера + служебные байты)
        $this->engineByteCount += count($padded);

        // ИСПРАВЛЕНО: раньше здесь пересчитывалось задним числом
        // (count($this->paddedKey) + count($padded) + count($this->invertedKey)),
        // что игнорировало байты сообщения, отправленные НАПРЯМУЮ во время
        // update() (когда буфер оставался пустым при полностью кратной блоку
        // длине сообщения — ровно случай testOverflow1024Bytes).
        // Теперь берём фактический счётчик всех байт, когда-либо физически
        // отправленных в движок, плюс сырые байты invertedKey (без учёта
        // служебных байт самого padFinal — они, по конвенции construction'а
        // Меркла — Дамгора, в длину не входят).
        $totalConsumed = $this->engineByteCount + count($this->invertedKey);

        $finalPadded = $this->padFinal($this->invertedKey, $totalConsumed);
        $this->engine->updateRaw($finalPadded, 0, count($finalPadded));

        return $this->engine->finish();
    }

    public function reset()
    {
        $this->ensureInitialised();
        $this->buffer = array();
        $this->inputLength = 0;
        $this->newEngine();
        $this->engine->updateRaw($this->paddedKey, 0, count($this->paddedKey));
        // ДОБАВЛЕНО: счётчик тоже нужно сбросить и снова учесть paddedKey
        $this->engineByteCount = count($this->paddedKey);
        return $this;
    }

    private function newEngine()
    {
        $this->engine = new DSTU7564($this->macSize * 8);
    }

    private function padMessage($tail, $length)
    {
        $extra = $this->blockSize - ($length % $this->blockSize);
        if ($extra < 13) {
            $extra += $this->blockSize;
        }

        $padded = array_fill(0, count($tail) + $extra, 0);
        foreach ($tail as $i => $byte) {
            $padded[$i] = ((int)$byte) & 0xFF;
        }
        $padded[count($tail)] = 0x80;
        $this->writeLength96LE($padded, count($padded) - 12, $length * 8);
        return $padded;
    }

    /**
     * Финализирующий блок для invertedKey — по формату идентичен padMessage()
     * (8-байтная LE длина в битах), но длина считается от НАЧАЛА ВСЕГО потока,
     * когда-либо поглощённого движком ($totalConsumedBytes), а не только от
     * длины текущего фрагмента (invertedKey).
     */
    private function padFinal($tail, $totalConsumedBytes)
    {
        $tailLen = count($tail);
        $extra = $this->blockSize - ($tailLen % $this->blockSize);
        if ($extra < 13) {
            $extra += $this->blockSize;
        }

        $padded = array_fill(0, $tailLen + $extra, 0);
        foreach ($tail as $i => $byte) {
            $padded[$i] = ((int)$byte) & 0xFF;
        }
        $padded[$tailLen] = 0x80;
        $this->writeLength96LE($padded, count($padded) - 12, $totalConsumedBytes * 8);

        return $padded;
    }

    private function padKey($key)
    {
        $length = count($key);
        $paddedLen = intdiv($length + $this->blockSize - 1, $this->blockSize) * $this->blockSize;
        $extra = $this->blockSize - ($length % $this->blockSize);
        if ($extra < 13) {
            $paddedLen += $this->blockSize;
        }
        if ($paddedLen === 0) {
            $paddedLen = $this->blockSize;
        }

        $padded = array_fill(0, $paddedLen, 0);
        foreach ($key as $i => $byte) {
            $padded[$i] = ((int)$byte) & 0xFF;
        }
        $padded[$length] = 0x80;

        // Эталон (Bouncy Castle Dstu7564Mac.PadKey) использует Pack.UInt32_To_LE —
        // ровно 4 байта длины + 8 нулей после. Это единственное место во всём
        // классе, где длина кодируется 4 байтами, а не 8.
        $this->writeLength32LE($padded, $paddedLen - 12, $length * 8);

        return $padded;
    }

    private function writeLength96LE(&$buffer, $offset, $value)
    {
        $value = (int)$value;
        for ($i = 0; $i < 8; $i++) {
            $buffer[$offset + $i] = $value & 0xFF;
            $value = intdiv($value, 256);
        }
        $buffer[$offset + 8] = 0;
        $buffer[$offset + 9] = 0;
        $buffer[$offset + 10] = 0;
        $buffer[$offset + 11] = 0;
    }

    private function writeLength32LE(&$buffer, $offset, $value)
    {
        $value = (int)$value;
        for ($i = 0; $i < 4; $i++) {
            $buffer[$offset + $i] = $value & 0xFF;
            $value = intdiv($value, 256);
        }
        // Байты offset+4 .. offset+11 остаются нулевыми —
        // массив уже инициализирован нулями через array_fill().
    }

    private function toBytes($data)
    {
        if (is_string($data)) {
            $bytes = unpack('C*', $data);
            return $bytes ? array_values($bytes) : array();
        }
        if (!is_array($data)) {
            throw new \InvalidArgumentException('DSTU7564Mac data must be a byte array or binary string');
        }
        $result = array();
        foreach ($data as $byte) {
            $result[] = ((int)$byte) & 0xFF;
        }
        return $result;
    }

    private function ensureInitialised()
    {
        if ($this->key === null) {
            throw new \LogicException('DSTU7564Mac is not initialised');
        }
    }
	
	
    /**
     * PBKDF2 с PRF = DSTU7564Mac (режим ДСТУ 7564:2014 «Купина (КАП)»).
     *
     * @param string|array $password
     * @param string|array $salt
     * @param int $iterations
     * @param int $length желаемая длина производного ключа в байтах
     * @param int $macBits размер MAC в битах (256 для Kalyna-256/256)
     * @return string бинарная строка длиной $length байт
     */
    public static function pbkdf2($password, $salt, int $iterations, int $length, int $macBits = 256): string
    {
        if ($iterations <= 0) {
            throw new \InvalidArgumentException('PBKDF2 iterations must be greater than zero');
        }
        if ($length <= 0) {
            throw new \InvalidArgumentException('PBKDF2 output length must be greater than zero');
        }

        $self = new self($macBits); // только чтобы переиспользовать toBytes()
        $passwordBytes = $self->toBytes($password);
        $saltBytes     = $self->toBytes($salt);
        $hashLen       = intdiv($macBits, 8);
        $blocks        = (int)ceil($length / $hashLen);

        $derivedKey = '';

        for ($blockIndex = 1; $blockIndex <= $blocks; $blockIndex++) {
            $blockNumber = array_values(unpack('C*', pack('N', $blockIndex))); // INT(i), BE, 4 байта

            // U1 = MAC(password, salt || INT(i))
            $mac = new self($macBits);
            $mac->init($passwordBytes);
            $mac->update($saltBytes);
            $mac->update($blockNumber);
            $u = $mac->finish(); // массив байт
            $t = $u;

            // Uj = MAC(password, Uj-1);  T = U1 xor U2 xor ... xor Uc
            for ($j = 1; $j < $iterations; $j++) {
                $mac2 = new self($macBits);
                $mac2->init($passwordBytes);
                $mac2->update($u);
                $u = $mac2->finish();
                for ($k = 0; $k < count($t); $k++) {
                    $t[$k] ^= $u[$k];
                }
            }

            $derivedKey .= pack('C*', ...$t);
        }

        return substr($derivedKey, 0, $length);
    }
}