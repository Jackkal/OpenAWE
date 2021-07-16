/* OpenAWE - A reimplementation of Remedys Alan Wake Engine
 *
 * OpenAWE is the legal property of its developers, whose names
 * can be found in the AUTHORS file distributed with this source
 * distribution.
 *
 * OpenAWE is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * OpenAWE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenAWE. If not, see <http://www.gnu.org/licenses/>.
 */

#include <gtest/gtest.h>

#include "src/common/memreadstream.h"

#include "src/awe/binarchive.h"

// Generated by https://www.lipsum.com/
static const char* kLipsum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque nec urna ex. Duis eu "
                             "facilisis ipsum. Phasellus ultricies et enim vitae scelerisque. Maecenas faucibus sem "
                             "nec neque fermentum pretium. Sed sed aliquam ligula, at tincidunt velit. Curabitur sit "
                             "amet tellus sed arcu varius egestas. Vivamus eu mi nec leo accumsan consectetur sit amet "
                             "a arcu. Vivamus auctor dui a ex sodales, vitae sagittis elit euismod. Sed posuere luctus "
                             "rutrum. Morbi nunc nisl, faucibus sed varius ut, volutpat vel turpis. Phasellus "
                             "dignissim, purus id pretium mattis, purus ante auctor metus, sit amet ornare dolor diam "
                             "sit amet metus. Donec hendrerit venenatis enim, nec cursus nibh pharetra et.\n"
                             "\n"
                             "Cras tortor lacus, vestibulum eget dapibus tempus, vestibulum ut dui. Ut enim felis, "
                             "pharetra vitae hendrerit sit amet, bibendum ac tellus. Integer lacinia augue ante, in "
                             "volutpat sem luctus ut. Sed cursus fermentum vulputate. Nulla mollis pulvinar maximus. "
                             "Curabitur cursus ligula at congue fermentum. Proin gravida tellus non massa posuere "
                             "mattis quis id nisi. Duis ut vulputate quam. Curabitur ultrices arcu faucibus, "
                             "ullamcorper neque nec, mattis magna. Morbi commodo maximus eros in pharetra. Proin "
                             "elementum nisi non mi suscipit, nec molestie nunc aliquet. In facilisis nisl id erat "
                             "suscipit aliquam. Integer tempor venenatis velit id vehicula. In sagittis accumsan "
                             "pharetra. Vestibulum volutpat nisi in sem tristique, elementum tempus erat eleifend.\n"
                             "\n"
                             "Maecenas porta erat lectus, sit amet aliquam ante commodo pharetra. Nunc venenatis "
                             "tempor ex, eget venenatis urna iaculis vitae. Morbi suscipit purus nec erat pharetra "
                             "tincidunt. Nunc lectus dui, molestie et urna vitae, laoreet elementum nisi. Vestibulum "
                             "viverra porttitor lacus sed elementum. Etiam feugiat ornare luctus. Mauris in dui "
                             "facilisis, bibendum odio mollis, gravida quam. Proin vehicula non turpis nec dapibus. "
                             "Fusce nisl erat, sagittis non nisi eget, condimentum blandit nisi.\n"
                             "\n"
                             "Quisque blandit velit sed tempor ultrices. Proin at posuere quam. Suspendisse varius "
                             "justo magna. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur porta "
                             "nec turpis non vulputate. Suspendisse potenti. Vivamus vitae sollicitudin metus. "
                             "Curabitur non neque nibh.\n"
                             "\n"
                             "Sed non rhoncus nisi. Aenean sed mauris eleifend, commodo sem et, aliquet velit. Sed "
                             "posuere posuere purus, nec finibus nunc gravida a. Morbi id ligula lorem. Phasellus sit "
                             "amet tortor in mauris luctus porta vel a nulla. Donec ultrices nibh sit amet "
                             "urna malesuada, in fermentum nisi tincidunt. Praesent fringilla euismod ipsum, quis "
                             "lobortis velit tristique ut. Proin ac est in nunc gravida molestie. Ut non eros libero. "
                             "Ut auctor at justo a dignissim. In in venenatis nulla. Quisque ut fringilla massa, "
                             "maximus facilisis dui. Morbi et convallis tortor. Morbi ut odio non est consectetur "
                             "fringilla. Orci varius natoque penatibus et magnis dis parturient montes, nascetur "
                             "ridiculus mus. Mauris lacinia dapibus pharetra. \n";

static const byte kEmptyBin[] = {
	0x00, 0x00, 0x00, 0x00, 0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const byte kMultipleFilesBin[] = {
	0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74,
	0x2e, 0x74, 0x78, 0x74, 0x0c, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
	0x74, 0x65, 0x73, 0x74, 0x32, 0x2e, 0x74, 0x78, 0x74, 0x0e, 0x00, 0x00,
	0x00, 0x09, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x33, 0x2e, 0x74,
	0x78, 0x74, 0x74, 0x0b, 0x00, 0x00, 0x78, 0x9c, 0x9d, 0x56, 0xcb, 0x8e,
	0xdc, 0x36, 0x10, 0xbc, 0xef, 0x57, 0x74, 0xee, 0xc2, 0x7c, 0x40, 0x6e,
	0x81, 0x9d, 0xc0, 0x01, 0x62, 0xc7, 0x81, 0x11, 0xe7, 0xcc, 0x91, 0x38,
	0x33, 0x1d, 0x50, 0xa4, 0x96, 0x8f, 0xc1, 0x7e, 0x7e, 0xaa, 0x9b, 0x2f,
	0xad, 0x8f, 0x39, 0xed, 0x8e, 0x1e, 0xec, 0xea, 0xea, 0xaa, 0x6a, 0x7d,
	0xb2, 0xce, 0x05, 0xfa, 0x27, 0x44, 0xb7, 0xfd, 0xf4, 0x69, 0xfe, 0x4f,
	0x3f, 0x7f, 0xfc, 0x23, 0x44, 0xbb, 0x13, 0x1f, 0xa9, 0xec, 0xb4, 0x05,
	0x17, 0x22, 0x25, 0xce, 0x64, 0x76, 0x9b, 0x17, 0x5a, 0x83, 0x4f, 0x76,
	0xcd, 0x36, 0x97, 0x48, 0x66, 0xe3, 0x83, 0xd3, 0xca, 0xfe, 0x4e, 0xd6,
	0x71, 0xbe, 0xd0, 0x5f, 0x85, 0xd3, 0x6b, 0xb1, 0xe4, 0xed, 0x4a, 0x25,
	0x7a, 0x43, 0xf6, 0xed, 0x42, 0x1f, 0x71, 0x91, 0x6c, 0xa1, 0x9b, 0x59,
	0xd9, 0x71, 0xc2, 0x0f, 0x3d, 0xf9, 0x42, 0x5f, 0x1f, 0x26, 0xa1, 0x6e,
	0x49, 0x54, 0x5c, 0x8e, 0xbc, 0xb2, 0xc5, 0x73, 0x99, 0xac, 0xe7, 0x9d,
	0x9e, 0x9c, 0x8d, 0xa5, 0xb4, 0x5a, 0x67, 0xa3, 0x9e, 0x79, 0xa1, 0xcf,
	0xc6, 0xae, 0xd6, 0x9b, 0x84, 0x83, 0xca, 0xca, 0x57, 0xbc, 0x96, 0x80,
	0x52, 0x4a, 0x79, 0x2b, 0x45, 0x6f, 0x36, 0xee, 0xd6, 0x67, 0x60, 0x3e,
	0xa2, 0xcd, 0x2c, 0x15, 0xbe, 0xd9, 0x0d, 0x0f, 0x6d, 0x64, 0x1c, 0xbf,
	0x16, 0xb3, 0x93, 0xe3, 0x7b, 0x71, 0x66, 0x21, 0x93, 0x29, 0xb3, 0x5f,
	0x79, 0x2b, 0x3e, 0xd3, 0xb3, 0x62, 0xff, 0x50, 0xa2, 0xb9, 0xb2, 0xb4,
	0xd5, 0x9b, 0xa5, 0x5c, 0xd1, 0xe9, 0x09, 0x71, 0x2d, 0xf4, 0x34, 0x91,
	0xf1, 0xdb, 0xde, 0x6d, 0xca, 0x26, 0x5d, 0xe8, 0x3b, 0x3f, 0xcd, 0x5e,
	0xb4, 0xb9, 0x9d, 0x15, 0x89, 0xb3, 0x81, 0xcc, 0xba, 0x96, 0x3d, 0x19,
	0xff, 0x8e, 0xaa, 0x71, 0xa6, 0xd1, 0xa3, 0xe6, 0xbb, 0xe8, 0x25, 0x83,
	0xe0, 0xad, 0x30, 0x09, 0x5d, 0x94, 0xc2, 0x66, 0x9c, 0x4d, 0x4b, 0x67,
	0xc0, 0xdc, 0x39, 0x67, 0x21, 0x10, 0x20, 0x51, 0x88, 0xd3, 0x1e, 0xb6,
	0xda, 0xd8, 0x11, 0x52, 0xb1, 0xd1, 0x92, 0xc3, 0x09, 0x38, 0x28, 0x96,
	0x1c, 0xa5, 0xe7, 0xcf, 0x21, 0x5e, 0x01, 0xa6, 0x78, 0xf0, 0xc2, 0xc9,
	0x2d, 0x67, 0xba, 0xb6, 0xde, 0x42, 0xc1, 0x24, 0x9f, 0xc1, 0x95, 0x7c,
	0x18, 0x25, 0x80, 0x80, 0x11, 0xa3, 0x3c, 0xcf, 0x64, 0xe3, 0x3b, 0xde,
	0x4f, 0xbc, 0x2f, 0x74, 0x94, 0x88, 0x0b, 0xbc, 0x75, 0x62, 0x69, 0x37,
	0x82, 0xa9, 0xdf, 0x30, 0x3e, 0xdb, 0xde, 0x07, 0x5a, 0x2c, 0xb8, 0x31,
	0xda, 0x0d, 0x50, 0x01, 0x30, 0x56, 0x15, 0x6d, 0x8c, 0x19, 0x8c, 0x5b,
	0xfa, 0x28, 0xe4, 0x11, 0x84, 0xb8, 0x87, 0xf5, 0x5b, 0xc4, 0xa8, 0x05,
	0x8d, 0xc7, 0x94, 0xb5, 0x65, 0x2f, 0xc5, 0xe5, 0xee, 0x5a, 0x62, 0x42,
	0x21, 0xcf, 0xd7, 0x07, 0x1d, 0x0f, 0x1c, 0x98, 0x23, 0xc8, 0xca, 0x97,
	0x97, 0x97, 0x0f, 0x11, 0x82, 0x40, 0x61, 0xa9, 0xed, 0xcc, 0x2a, 0xb5,
	0x9f, 0x98, 0x0e, 0xfa, 0x75, 0xc0, 0x89, 0x49, 0x65, 0xda, 0xcc, 0xa1,
	0xed, 0x67, 0xbb, 0x1f, 0x3f, 0xdc, 0x2f, 0x59, 0x88, 0xbf, 0xd0, 0xdf,
	0x4d, 0x75, 0x37, 0xb0, 0x2c, 0x6d, 0xf5, 0x12, 0x75, 0x06, 0x13, 0xdb,
	0xb4, 0xc1, 0x95, 0xaf, 0xb8, 0x8a, 0x23, 0xcc, 0xda, 0x64, 0x72, 0xa1,
	0xdf, 0xc1, 0xc3, 0xdd, 0x2a, 0x0e, 0xf6, 0x8c, 0x41, 0x97, 0x3b, 0x64,
	0x29, 0xec, 0x2c, 0xc4, 0x7e, 0xf2, 0x2d, 0xb2, 0x6d, 0x43, 0x2b, 0xb9,
	0xce, 0xb2, 0x35, 0x38, 0x25, 0xfc, 0x2c, 0xee, 0x28, 0xd9, 0x64, 0xe8,
	0xfe, 0x4b, 0x71, 0xce, 0xd0, 0x1e, 0x1c, 0xb0, 0x81, 0x71, 0xf7, 0x64,
	0x50, 0x8a, 0x11, 0xbc, 0xf1, 0x2e, 0x55, 0xa7, 0x6e, 0xdb, 0x21, 0x55,
	0xe4, 0xa2, 0x71, 0x08, 0xf0, 0x7e, 0x36, 0x06, 0xc6, 0x1b, 0x03, 0x90,
	0xdc, 0xa3, 0x79, 0xf2, 0x66, 0xba, 0xbe, 0x7d, 0xf0, 0x38, 0x2e, 0x25,
	0x33, 0x24, 0x55, 0xe7, 0x4b, 0xaf, 0xe2, 0x5c, 0x8c, 0x1d, 0x3a, 0xe0,
	0xe6, 0x63, 0x30, 0x36, 0xa0, 0x91, 0x78, 0xea, 0x0c, 0xa0, 0xda, 0x18,
	0x2e, 0x56, 0xb7, 0x74, 0xdd, 0x2d, 0x24, 0x0d, 0xec, 0x6b, 0x88, 0x07,
	0xc8, 0xa9, 0x5e, 0xc5, 0x50, 0x97, 0x5e, 0x65, 0x37, 0x77, 0x6f, 0xba,
	0x6e, 0xd7, 0xb0, 0x43, 0xe0, 0xa1, 0xb7, 0x47, 0x36, 0x86, 0x24, 0xe4,
	0xf5, 0x91, 0xf4, 0x16, 0x90, 0x0b, 0x8d, 0x29, 0x01, 0x57, 0x5b, 0x60,
	0x42, 0xfb, 0x2b, 0x22, 0x29, 0x57, 0xd5, 0x80, 0x32, 0x19, 0xb5, 0xad,
	0x66, 0xd0, 0x0c, 0x80, 0x66, 0x30, 0xa6, 0x53, 0x14, 0x89, 0x45, 0xa4,
	0x45, 0x1b, 0x65, 0x30, 0xed, 0xf5, 0x9e, 0x17, 0x73, 0xa4, 0xa2, 0x1d,
	0x28, 0x6c, 0x6a, 0x53, 0x43, 0x43, 0x5e, 0x7c, 0xda, 0x07, 0xaf, 0xe0,
	0x5b, 0xcf, 0x1d, 0x6e, 0x1d, 0x19, 0x30, 0x71, 0x7f, 0x9f, 0xb2, 0x1b,
	0x4a, 0x50, 0xec, 0xe8, 0x46, 0x14, 0x01, 0xea, 0xf0, 0x00, 0x20, 0x2e,
	0xa7, 0xe6, 0xaa, 0x66, 0x2b, 0x3a, 0x5c, 0xe5, 0x1b, 0x44, 0x07, 0xd5,
	0x8f, 0x28, 0x04, 0xa8, 0x6c, 0xea, 0x6d, 0x67, 0xd7, 0xf7, 0xd6, 0xeb,
	0xa1, 0xa7, 0xf6, 0xec, 0xbc, 0x4e, 0x3c, 0x5f, 0x84, 0x94, 0xd9, 0x50,
	0xeb, 0xd0, 0xbe, 0x2d, 0xd5, 0x35, 0xf3, 0x8e, 0x06, 0x39, 0xc3, 0x5b,
	0xa2, 0x3f, 0x75, 0x44, 0x1f, 0xd6, 0xe0, 0xab, 0xe6, 0x80, 0x70, 0xae,
	0x50, 0x86, 0x7f, 0x46, 0xc8, 0xb6, 0x72, 0x15, 0xa3, 0x78, 0x6e, 0x99,
	0xd3, 0x41, 0x31, 0x2d, 0xa1, 0x47, 0x2f, 0x70, 0x0f, 0xb6, 0x8f, 0xcd,
	0x3f, 0x4c, 0xf8, 0x3d, 0x7f, 0xfc, 0xb4, 0x31, 0x1a, 0xed, 0x3e, 0xf3,
	0xb0, 0xbe, 0x06, 0xdc, 0x78, 0xed, 0x42, 0xbf, 0x66, 0xc9, 0x9b, 0x9b,
	0x2d, 0x77, 0x36, 0x23, 0x89, 0xaa, 0xf1, 0x64, 0x9b, 0x94, 0xc8, 0x2a,
	0x2d, 0x89, 0xde, 0x21, 0x88, 0x93, 0xb3, 0xc3, 0xc6, 0xa1, 0xd9, 0x6e,
	0x19, 0x96, 0xa9, 0xb2, 0xa8, 0x1a, 0xec, 0xa3, 0x57, 0xf5, 0xd5, 0x00,
	0x55, 0x0e, 0x5a, 0xe0, 0x5c, 0xe8, 0x37, 0xf0, 0x63, 0xab, 0xc4, 0x84,
	0x97, 0x65, 0xea, 0x43, 0xde, 0xd0, 0xe1, 0x0b, 0xd7, 0xba, 0x54, 0x37,
	0x6e, 0xdd, 0x5e, 0x9d, 0xc1, 0x8f, 0xaa, 0x0d, 0x8c, 0xba, 0xaf, 0xd4,
	0x7e, 0xb9, 0x0a, 0x4f, 0x3a, 0x6d, 0x13, 0xeb, 0xa6, 0xeb, 0xa8, 0x84,
	0xff, 0x66, 0xe3, 0x0a, 0xf6, 0x5b, 0x49, 0x07, 0x3a, 0x42, 0x96, 0xdb,
	0x1e, 0xff, 0xff, 0x96, 0x94, 0x43, 0x37, 0xde, 0xff, 0xde, 0xf6, 0xd3,
	0xf8, 0x55, 0x86, 0xd2, 0x7b, 0xa7, 0x01, 0xfd, 0x9d, 0x22, 0xec, 0x0c,
	0xe1, 0x08, 0x19, 0x8d, 0xf2, 0xdc, 0x80, 0x6d, 0xd1, 0x09, 0xd1, 0x2b,
	0x4e, 0xdb, 0xd0, 0x43, 0x5b, 0x0d, 0xb3, 0x80, 0xf2, 0x55, 0x93, 0x03,
	0x3b, 0x00, 0xb4, 0x48, 0x68, 0xca, 0xc5, 0xf8, 0x08, 0x7e, 0xd5, 0xd5,
	0x20, 0x1a, 0xf9, 0x05, 0xa2, 0x35, 0x5e, 0xd9, 0xd9, 0xeb, 0x7c, 0xbb,
	0x69, 0x96, 0xe1, 0x00, 0xf1, 0x9a, 0xb4, 0xd6, 0xf2, 0xa0, 0xaf, 0xff,
	0xf3, 0x46, 0x1d, 0x7f, 0x45, 0xd6, 0x35, 0x4b, 0x6e, 0x48, 0x74, 0x59,
	0x22, 0x1a, 0x25, 0x5d, 0x0c, 0x23, 0xb5, 0x90, 0x03, 0x2d, 0x75, 0x9d,
	0x90, 0x79, 0x5e, 0xa3, 0xf3, 0x63, 0xa2, 0x2e, 0x29, 0xe9, 0xae, 0x42,
	0x6b, 0x2b, 0xa0, 0x72, 0x27, 0x3b, 0x18, 0x0c, 0x4a, 0x52, 0xf6, 0x95,
	0x38, 0xd2, 0x54, 0xd7, 0xde, 0x38, 0x47, 0xbd, 0xb2, 0xcb, 0x37, 0x42,
	0x31, 0x9b, 0xd1, 0xcd, 0x32, 0xd7, 0x86, 0x6a, 0xea, 0xe4, 0xba, 0xaf,
	0xd1, 0xd8, 0x84, 0x5b, 0x74, 0x8b, 0x98, 0x1b, 0xcb, 0x22, 0x69, 0xdf,
	0x10, 0x75, 0xe0, 0x4b, 0xcd, 0x78, 0x17, 0xae, 0x40, 0x31, 0x62, 0x6d,
	0x44, 0x91, 0xee, 0xa7, 0x26, 0x2b, 0x78, 0x3b, 0x65, 0xa9, 0xf6, 0x8e,
	0x82, 0xee, 0x62, 0xdd, 0xa1, 0x32, 0x10, 0x0d, 0x6c, 0x07, 0x0f, 0xc5,
	0xa0, 0xd7, 0xda, 0x77, 0x01, 0x54, 0x59, 0x45, 0x67, 0xe6, 0x87, 0x85,
	0x46, 0xa6, 0xfa, 0xa8, 0x47, 0x4d, 0xeb, 0xbf, 0x6b, 0xbe, 0x9c, 0x71,
	0xeb, 0x86, 0x5a, 0xc6, 0x62, 0x98, 0x11, 0xae, 0x1b, 0xbc, 0xce, 0xc1,
	0xea, 0xce, 0x7b, 0x1a, 0x5d, 0x95, 0x95, 0xf0, 0x7e, 0x0b, 0x67, 0xa9,
	0xa1, 0x15, 0x63, 0xca, 0xef, 0x94, 0x3d, 0x8a, 0x5c, 0xe8, 0xcf, 0xb8,
	0x72, 0x77, 0x09, 0x30, 0x05, 0x81, 0x71, 0x28, 0x3a, 0x99, 0xbe, 0x7c,
	0xb5, 0x18, 0x41, 0x8f, 0x26, 0x30, 0x39, 0x13, 0xf1, 0x36, 0x0b, 0xbd,
	0x7b, 0x40, 0xc8, 0x8a, 0x54, 0x0c, 0x1c, 0x2f, 0x47, 0x46, 0xde, 0x24,
	0x1b, 0xf0, 0xce, 0x7e, 0x4a, 0x9b, 0xfe, 0x65, 0xd0, 0x3f, 0x49, 0x66,
	0x1a, 0xbf, 0xfc, 0x07, 0x22, 0x36, 0x3f, 0x07
};

TEST(BINArchive, EmptyArchive) {
	Common::MemoryReadStream bin(const_cast<byte *>(kEmptyBin), sizeof(kEmptyBin), false);

	AWE::BINArchive binArchive(bin);

	EXPECT_EQ(binArchive.getNumResources(), 0);

	EXPECT_EQ(binArchive.getResource("test.txt"), nullptr);
	EXPECT_TRUE(binArchive.hasDirectory(""));
	EXPECT_FALSE(binArchive.hasDirectory("test"));
	EXPECT_FALSE(binArchive.hasResource("not_found.txt"));
	EXPECT_FALSE(binArchive.hasResource("not_found2.txt"));
}

TEST(BINArchive, MultipleFiles) {
	Common::MemoryReadStream bin(const_cast<byte *>(kMultipleFilesBin), sizeof(kMultipleFilesBin), false);

	AWE::BINArchive binArchive(bin);

	EXPECT_EQ(binArchive.getNumResources(), 3);

	EXPECT_TRUE(binArchive.hasDirectory(""));
	EXPECT_FALSE(binArchive.hasDirectory("test"));
	EXPECT_TRUE(binArchive.hasResource("test.txt"));
	EXPECT_TRUE(binArchive.hasResource("test2.txt"));
	EXPECT_TRUE(binArchive.hasResource("test3.txt"));
	EXPECT_FALSE(binArchive.hasResource("not_found.txt"));
	EXPECT_FALSE(binArchive.hasResource("not_found2.txt"));

	std::unique_ptr<Common::ReadStream> test1(binArchive.getResource("test.txt"));
	std::unique_ptr<Common::ReadStream> test2(binArchive.getResource("test2.txt"));
	std::unique_ptr<Common::ReadStream> test3(binArchive.getResource("test3.txt"));

	ASSERT_TRUE(test1);
	ASSERT_TRUE(test2);
	ASSERT_TRUE(test3);

	std::string test1Text = test1->readNullTerminatedString();
	std::string test2Text = test2->readNullTerminatedString();
	std::string test3Text = test3->readNullTerminatedString();

	EXPECT_STREQ(test1Text.c_str(), "Hello World!");
	EXPECT_STREQ(test2Text.c_str(), "Hello World :D");
	EXPECT_STREQ(test3Text.c_str(), kLipsum);
}
