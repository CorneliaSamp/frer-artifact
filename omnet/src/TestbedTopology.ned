//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

package frer_experiments;


import inet.node.tsn.TsnDevice;
import inet.node.tsn.TsnSwitch;
import inet.node.ethernet.EthernetLink;
import inet.networks.base.TsnNetworkBase;

network FRERTestNetwork extends TsnNetworkBase
{
    parameters:
        @display("bgb=1000,600");

    submodules:
        talker: TsnDevice {
            @display("p=70,242");
        }

        attacker: TsnDevice {
            @display("p=335,539");
        }

        listener: TsnDevice {
            @display("p=882,242");
        }

        S1: TsnSwitch {
            @display("p=312,195");
        }

        S2: TsnSwitch {
            @display("p=479,193");
        }

        S3: TsnSwitch {
            @display("p=481,414");
        }

        S4: TsnSwitch {
            @display("p=647,193");
        }

    connections:
        // two disjoint paths talker->listener, S4 is the merge point
        talker.ethg++ <--> EthernetLink <--> S1.ethg++;
        S1.ethg++ <--> EthernetLink <--> S2.ethg++;
        S2.ethg++ <--> EthernetLink <--> S4.ethg++;
        S4.ethg++ <--> EthernetLink <--> listener.ethg++;

        S1.ethg++ <--> EthernetLink <--> S3.ethg++;
        S3.ethg++ <--> EthernetLink <--> S4.ethg++;

        // attacker hangs off S3 on the second path
        attacker.ethg++ <--> EthernetLink <--> S3.ethg++;
}
