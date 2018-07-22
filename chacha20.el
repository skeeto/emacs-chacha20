;;; chacha20.el --- ChaCha20 keystream generator -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;; ChaCha20 is a state of the art stream cipher developed by Daniel J.
;; Bernstein in 2008. It accepts a 256-bit key and 64-bit nonce/IV.

;; Since ChaCha20 uses 32-bit unsigned integer operations, this
;; library requires that Emacs is built with integers at least 32 bits
;; wide. Typically this means you need a 64-bit build of Emacs.

;;; Code:

(require 'ert)
(require 'cl-lib)

(defsubst chacha20--unpack (string i)
  "Parse a 32-bit little endian integer from unibyte STRING at offset I."
  (logior      (aref string i)
          (lsh (aref string (+ i 1))  8)
          (lsh (aref string (+ i 2)) 16)
          (lsh (aref string (+ i 3)) 24)))

(defsubst chacha20--pack (string i v)
  "Write 32-bit little endian integer V into unibyte STRING at offset I."
  (prog1 string
    (setf (aref string i) (logand v #xff)
          (aref string (+ i 1)) (logand (lsh v -8) #xff)
          (aref string (+ i 2)) (logand (lsh v -16) #xff)
          (aref string (+ i 3)) (lsh v -24))))

(defsubst chacha20--rotate (v n)
  "Left rotate 32-bit integer V by N bits."
  (logior (logand (lsh v n) #xffffffff)
          (lsh v (- n 32))))

(defsubst chacha20--+ (a b)
  "Add A and B modulo 2^32."
  (logand (+ a b) #xffffffff))

(defsubst chacha20--quarterround (s a b c d)
  (setf (aref s a) (chacha20--+ (aref s a) (aref s b))
        (aref s d) (chacha20--rotate (logxor (aref s d) (aref s a)) 16)
        (aref s c) (chacha20--+ (aref s c) (aref s d))
        (aref s b) (chacha20--rotate (logxor (aref s b) (aref s c)) 12)
        (aref s a) (chacha20--+ (aref s a) (aref s b))
        (aref s d) (chacha20--rotate (logxor (aref s d) (aref s a))  8)
        (aref s c) (chacha20--+ (aref s c) (aref s d))
        (aref s b) (chacha20--rotate (logxor (aref s b) (aref s c))  7)))

(defun chacha20-create (key iv)
  "Create a ChaCha20 context from a 32-byte key and 8-byte IV.
Both inputs must be unibyte strings."
  (cl-assert (= (length key) 32))
  (cl-assert (and (stringp key) (not (multibyte-string-p key))))
  (cl-assert (= (length iv) 8))
  (cl-assert (and (stringp iv) (not (multibyte-string-p iv))))
  (vector #x61707865  ; "expand 32-byte k"
          #x3320646e  ;
          #x79622d32  ;
          #x6b206574  ;
          (chacha20--unpack key 0)
          (chacha20--unpack key 4)
          (chacha20--unpack key 8)
          (chacha20--unpack key 12)
          (chacha20--unpack key 16)
          (chacha20--unpack key 20)
          (chacha20--unpack key 24)
          (chacha20--unpack key 28)
          0
          0
          (chacha20--unpack iv 0)
          (chacha20--unpack iv 4)))

(defun chacha20-unpacked (context)
  "Generate the next 16 32-bit integers from CONTEXT."
  ;; Would using a pre-allocated vector be faster? Since copy-sequence
  ;; is implemented in C, it may be faster to use it and make garbage
  ;; rather than copy 16 elements into a pre-allocated vector in Emacs
  ;; Lisp.
  (let ((x (copy-sequence context)))
    (prog1 x
      (dotimes (_ 10) ; 20 rounds
        (chacha20--quarterround x 0  4  8 12)
        (chacha20--quarterround x 1  5  9 13)
        (chacha20--quarterround x 2  6 10 14)
        (chacha20--quarterround x 3  7 11 15)
        (chacha20--quarterround x 0  5 10 15)
        (chacha20--quarterround x 1  6 11 12)
        (chacha20--quarterround x 2  7  8 13)
        (chacha20--quarterround x 3  4  9 14))
      (dotimes (i 16)
        (setf (aref x i) (chacha20--+ (aref x i) (aref context i))))
      (when (eql (cl-incf (aref context 12)) #x100000000)
        (setf (aref context 12) 0)
        (cl-incf (aref context 13))))))

(defun chacha20 (context)
  "Generate the next 64 bytes from CONTEXT."
  ;; Would using a pre-allocated results string be faster?
  (let ((next (chacha20-unpacked context))
        (result (make-string 64 0)))
    (prog1 result
      (dotimes (i 16)
        (chacha20--pack result (* i 4) (aref next i))))))

;; Tests

(ert-deftest chacha20 ()
  (let ((context (chacha20-create (make-string 32 0) (make-string 8 0))))
    ;; Official IETF test vectors for 20 rounds on a zero key and IV
    (should (equal (chacha20 context)
                   (unibyte-string
                    #x76 #xb8 #xe0 #xad #xa0 #xf1 #x3d #x90
                    #x40 #x5d #x6a #xe5 #x53 #x86 #xbd #x28
                    #xbd #xd2 #x19 #xb8 #xa0 #x8d #xed #x1a
                    #xa8 #x36 #xef #xcc #x8b #x77 #x0d #xc7
                    #xda #x41 #x59 #x7c #x51 #x57 #x48 #x8d
                    #x77 #x24 #xe0 #x3f #xb8 #xd8 #x4a #x37
                    #x6a #x43 #xb8 #xf4 #x15 #x18 #xa1 #x1c
                    #xc3 #x87 #xb6 #x69 #xb2 #xee #x65 #x86)))
    (should (equal (chacha20 context)
                   (unibyte-string
                    #x9f #x07 #xe7 #xbe #x55 #x51 #x38 #x7a
                    #x98 #xba #x97 #x7c #x73 #x2d #x08 #x0d
                    #xcb #x0f #x29 #xa0 #x48 #xe3 #x65 #x69
                    #x12 #xc6 #x53 #x3e #x32 #xee #x7a #xed
                    #x29 #xb7 #x21 #x76 #x9c #xe6 #x4e #x43
                    #xd5 #x71 #x33 #xb0 #x74 #xd8 #x39 #xd5
                    #x31 #xed #x1f #x28 #x51 #x0a #xfb #x45
                    #xac #xe1 #x0a #x1f #x4b #x79 #x4d #x6f)))))

(provide 'chacha20)

;;; chacha20.el ends here
