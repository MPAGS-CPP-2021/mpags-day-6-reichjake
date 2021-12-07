#ifndef MPAGSCIPHER_CIPHER_HPP
#define MPAGSCIPHER_CIPHER_HPP

#include "CipherMode.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * \file Cipher.hpp
 * \brief Contains the declaration of the purely abstract Cipher base class
 */

/**
 * \class Cipher
 * \brief Defines the interface for a cipher
 *
 * A purely abstract base class that defines the interface for a cipher
 *
 * It can be used as follows:
 * \code{.cpp}
 * class MyCipher : public Cipher {...};
 * \endcode
 */
class Cipher {
  public:
    /**
     * \brief Apply the cipher to the provided text
     *
     * \param inputText the text to encrypt or decrypt
     * \param cipherMode whether to encrypt or decrypt the input text
     * \return the result of applying the cipher to the input text
     */
    virtual std::string applyCipher(const std::string& inputText,
                                    const CipherMode cipherMode) const = 0;

    /**
     * \brief split input text into substrings, each substring gets processed by a different thread
     *
     * \param str the text to be split up
     * \param n number of threads
     */
    std::vector <std::string> splitString(std::string str, int n)
    {
     int str_length = str.size();
     int part_size = str_length / n; // length of each substring
     std::vector <std::string> substrings{};


     for (int i = 0; i < str_length; i= i+part_size)
     {
       if (str_length % n != 0) // can't divide into equal parts
       {
         if( i + part_size >=  str_length ) // end of the string
         {
           substrings.push_back(str.substr(i,str_length-1));
         }
         else
         {
           substrings.push_back(str.substr(i,i+part_size));
         }
       }
       else // can be equally divided
       {
         substrings.push_back(str.substr(i,i+part_size));
       }
     }

     return substrings;
    }



    /// Default constructor
    Cipher() = default;
    /// Default copy constructor
    Cipher(const Cipher& rhs) = default;
    /// Default move constructor
    Cipher(Cipher&& rhs) = default;
    /// Default copy assignment operator
    Cipher& operator=(const Cipher& rhs) = default;
    /// Default move assignment operator
    Cipher& operator=(Cipher&& rhs) = default;
    /// Make the default destructor virtual
    virtual ~Cipher() = default;
};

class InvalidKey : public std::invalid_argument{
  public:

  InvalidKey(const std::string& what) :
  std::invalid_argument(what) {}

};





#endif
