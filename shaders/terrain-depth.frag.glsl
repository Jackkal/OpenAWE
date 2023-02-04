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

#version 330 core

in vec4 pass_ClipPosition;
in vec4 pass_ViewPosition;
in vec4 pass_Normal;

layout(location=0) out vec4 out_Depth;
layout(location=1) out vec4 out_Normal;

void main() {
    out_Depth = vec4(pass_ClipPosition.zzz / pass_ClipPosition.w, 1.0);
    out_Normal = pass_Normal * 0.5 + 0.5;
}
